// Package netretain is the retention consumer of a sensor's alert stream
// (P4-4-B5 deliverable 4, docs/phase4/D5-c5-0.9.md section 3, C8 0.12
// store.retention_moved). With no alert forward target, nothing else would
// ever prune the stream, so the node runs this required local consumer on
// it: at most once an hour it moves past the alerts older than the
// retention, and it records each move in the audit stream before its cursor
// commits.
//
// The cutoff advances no faster than the node's monotonic clock, so a
// forward step of the wall clock can't prune early: each move takes the
// earlier of the wall time less the retention and the previous recorded
// cutoff plus the monotonic time since that move. After a start, the
// monotonic time since the last move is unknown, so the previous cutoff plus
// StartAllowance stands in for it. A forward step therefore gains at most
// StartAllowance per restart, and each restart is an audited service.start.
//
// The consumer does no I/O of its own beyond its Store and its Record
// callback, and reads time only from its two clock seams, so a test can
// drive the wall clock and the monotonic clock apart. The runtime wiring
// (the hourly call, the audit write, status) is the node's.
package netretain

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
)

// ConsumerID is the retention consumer's C5 consumer of the alert stream.
const ConsumerID c5.ConsumerID = "node-retention"

// Interval is the least monotonic time between two evaluations in one run:
// the consumer moves at most once an hour (D5-c5-0.9 section 3).
const Interval = time.Hour

// StartAllowance is how far past the persisted cutoff the first move after
// a start may go, beyond the monotonic time since the start.
const StartAllowance = time.Hour

// Store is what the consumer needs of the network database: the commit
// index, one read for the oldest unpassed alert's commit time, and its
// cursor. platform/store.DB provides it.
type Store interface {
	LastCommitted(ctx context.Context, stream c5.StreamID) (c5.Seq, error)
	LastCommittedBy(ctx context.Context, stream c5.StreamID, t time.Time) (c5.Seq, error)
	FirstRetained(ctx context.Context, stream c5.StreamID) (c5.Seq, error)
	Read(ctx context.Context, stream c5.StreamID, after c5.Seq, max int) ([]c5.Stored, error)
	LoadCursors(ctx context.Context, stream c5.StreamID) ([]c5.Cursor, error)
	SaveCursor(ctx context.Context, c c5.Cursor) error
	// RaiseWallMark raises the database's wall mark, the floor of every
	// later commit time, to the clock now. The consumer calls it at each
	// evaluation, so an alert committed while the clock is stepped back
	// lands no lower than the wall time of the last evaluation, even on a
	// database idle since its last commit (D3's F2 on #559).
	RaiseWallMark(ctx context.Context) error
}

// Config is one sensor's consumer.
type Config struct {
	SensorID string
	// Retention is how long an alert is kept, in whole seconds.
	Retention time.Duration
}

// Options are the consumer's seams.
type Options struct {
	Store Store
	// Wall is the wall clock; Mono the node's monotonic clock, as the time
	// since some fixed point in this run.
	Wall func() time.Time
	Mono func() time.Duration
	// Record commits one store.retention_moved record for the sensor and
	// returns only once it is committed. On an error nothing moves.
	Record func(ctx context.Context, r audit.Retention) error
	// Latest reads the sensor's latest retained store.retention_moved
	// record, as Start's last. After a Record error the consumer reads it
	// before its next move, since a record can commit and still report an
	// error (C5's Append on a cancelled context; D6's R1 on #559).
	Latest func(ctx context.Context) (*audit.Retention, error)
}

// Consumer is one sensor's retention consumer. Its methods are safe for
// concurrent use.
type Consumer struct {
	cfg    Config
	opt    Options
	stream c5.StreamID

	mu sync.Mutex
	// cursor is the last recorded to_seq, and saved whether the store's
	// cursor has reached it.
	cursor c5.Seq
	saved  bool
	// cutoff is the last recorded cutoff. The monotonic bound is base plus
	// the monotonic time since baseMono; afterStart says that base still
	// holds StartAllowance.
	cutoff     time.Time
	base       time.Time
	baseMono   time.Duration
	afterStart bool
	evaluated  bool
	lastEval   time.Duration
	wallCut    time.Time
	monoCut    time.Time
	// jumped is whether Start found the store's cursor past the latest
	// record, and jumpedFrom that record's to_seq.
	jumped     bool
	jumpedFrom c5.Seq
	// resync is set by a Record error, with the monotonic time of the move
	// that failed: the next Tick reads the latest record first.
	resync     bool
	resyncMono time.Duration
}

// ErrConfig is a consumer that can't run as configured.
var ErrConfig = errors.New("netretain: config")

// Start opens the consumer. last is the stream's latest store.retention_moved
// record retained in the audit stream (Latest), or nil.
//
// With a record, the consumer resumes from it: its cursor is the record's
// to_seq, which Start saves if a crash came between the record and the
// cursor, and its first move after this start is bounded by the record's
// cutoff plus StartAllowance.
//
// With none, the consumer is created: it records bound created, from_seq =
// to_seq = its starting cursor, and a cutoff that is the commit time of the
// oldest alert after that cursor, or the wall time less the retention on an
// empty stream (C8 0.12 section 2.2). It passes nothing. A consumer whose
// latest record is no longer retained, because the audit stream was pruned
// past it, is created again the same way, which only keeps more.
//
// A store cursor past the latest record's to_seq is a move nothing
// recorded, since the consumer records before its cursor moves: a store
// edit or a bug. Start then creates the consumer at the store's cursor, so
// the audit stream shows the jump, and Status reports it as Unrecorded
// (D3 on #559).
func Start(ctx context.Context, cfg Config, opt Options, last *audit.Retention) (*Consumer, error) {
	if cfg.Retention < time.Second || cfg.Retention%time.Second != 0 {
		return nil, fmt.Errorf("%w: retention %s is not a whole number of seconds, 1 or more", ErrConfig, cfg.Retention)
	}
	if opt.Store == nil || opt.Wall == nil || opt.Mono == nil || opt.Record == nil || opt.Latest == nil {
		return nil, fmt.Errorf("%w: a seam is nil", ErrConfig)
	}
	c := &Consumer{cfg: cfg, opt: opt, stream: c5.StreamID(audit.AlertStreamPrefix + cfg.SensorID)}
	saved, err := c.savedCursor(ctx)
	if err != nil {
		return nil, err
	}
	if last != nil && last.Stream == string(c.stream) && c5.Seq(last.ToSeq) >= saved {
		cutoff, err := time.Parse(time.RFC3339Nano, last.CutoffUTC)
		if err != nil {
			return nil, fmt.Errorf("netretain: the latest record's cutoff: %w", err)
		}
		c.cursor, c.cutoff = c5.Seq(last.ToSeq), cutoff
		c.base, c.baseMono, c.afterStart = cutoff.Add(StartAllowance), opt.Mono(), true
		c.saveCursor(ctx, saved)
		return c, nil
	}
	if last != nil && last.Stream == string(c.stream) {
		c.jumped, c.jumpedFrom = true, c5.Seq(last.ToSeq)
	}
	if err := c.create(ctx, saved); err != nil {
		return nil, err
	}
	return c, nil
}

// create records the created record and then saves the starting cursor.
func (c *Consumer) create(ctx context.Context, saved c5.Seq) error {
	from := saved
	first, err := c.opt.Store.FirstRetained(ctx, c.stream)
	if err != nil {
		return err
	}
	if first == 0 {
		// Nothing is stored: every seq committed so far is gone.
		last, err := c.opt.Store.LastCommitted(ctx, c.stream)
		if err != nil {
			return err
		}
		from = max(from, last)
	} else {
		from = max(from, first-1)
	}
	wall := c.opt.Wall().Round(0).UTC()
	cutoff := wall.Add(-c.cfg.Retention)
	next, err := c.opt.Store.Read(ctx, c.stream, from, 1)
	if err != nil {
		return err
	}
	if len(next) > 0 {
		cutoff = next[0].CommittedAt.UTC()
	}
	r := audit.Retention{Stream: string(c.stream), FromSeq: uint64(from), ToSeq: uint64(from),
		RetentionS: int64(c.cfg.Retention / time.Second), WallUTC: utc(wall), CutoffUTC: utc(cutoff), Bound: audit.BoundCreated}
	if err := c.opt.Record(ctx, r); err != nil {
		return fmt.Errorf("netretain: created record: %w", err)
	}
	c.cursor, c.cutoff = from, cutoff
	c.base, c.baseMono = cutoff, c.opt.Mono()
	c.saveCursor(ctx, saved)
	return nil
}

// Tick evaluates a move, at most once per Interval of monotonic time in a
// run; the first call after Start evaluates at once, and so does every call
// after one that failed, so a stall stays an error until an evaluation
// succeeds (D6 on #559). It moves, writing the move's record first, only
// when the cutoff advances past the last recorded one and passes at least
// one alert. Otherwise it writes and persists nothing, which covers every
// tick while a backward clock step stalls the cutoff (C8 0.12 section 2.2).
//
// An error is the store's or the record's, and the consumer's cursor is
// then where it was. A record can commit and still report an error (C5's
// Append on a cancelled context), so after a Record error the next Tick
// first reads the latest record, and takes the move as made if that record
// is it (D6's R1 on #559).
func (c *Consumer) Tick(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resync {
		if err := c.resyncRecord(ctx); err != nil {
			return err
		}
	}
	if !c.saved {
		c.saveCursor(ctx, 0)
	}
	m := c.opt.Mono()
	if c.evaluated && m-c.lastEval < Interval {
		return nil
	}
	if err := c.evaluate(ctx, m); err != nil {
		return err
	}
	c.evaluated, c.lastEval = true, m
	return nil
}

// CatchUp is how much faster than the monotonic clock the bound advances:
// a move goes at most CatchUp times the monotonic time since the previous
// recorded move past its cutoff (or, after a start, past the cutoff plus
// StartAllowance), and never past the wall time less the retention. A lag
// behind the wall cutoff, from downtime, a forward clock correction, a cut
// to the retention, or a consumer created over old alerts, then closes at
// the monotonic rate, while a forward step of the wall clock prunes no
// faster than CatchUp times that rate (D1 in D4-71, D6's F3 on #559).
const CatchUp = 2

func (c *Consumer) evaluate(ctx context.Context, m time.Duration) error {
	if err := c.opt.Store.RaiseWallMark(ctx); err != nil {
		return err
	}
	wall := c.opt.Wall().Round(0).UTC()
	cutoff, bound := wall.Add(-c.cfg.Retention), audit.BoundWall
	mb := c.base.Add(CatchUp * (m - c.baseMono))
	if hold := latest(cutoff, c.cutoff); mb.After(hold) {
		// No lag: the bound is held at the wall cutoff, or at the recorded
		// cutoff while a backward step has the wall cutoff behind it, so
		// the catch-up can't build up a lead while the stream is idle that
		// a later forward step of the wall clock would spend at once. This
		// only lowers the bound.
		mb, c.base, c.baseMono, c.afterStart = hold, hold, m, false
	}
	c.wallCut, c.monoCut = cutoff, mb
	if mb.Before(cutoff) {
		cutoff, bound = mb, audit.BoundMonotonic
		if c.afterStart {
			bound = audit.BoundStart
		}
	}
	if !cutoff.After(c.cutoff) {
		return nil
	}
	to, err := c.opt.Store.LastCommittedBy(ctx, c.stream, cutoff)
	if err != nil {
		return err
	}
	if to <= c.cursor {
		return nil
	}
	r := audit.Retention{Stream: string(c.stream), FromSeq: uint64(c.cursor), ToSeq: uint64(to),
		RetentionS: int64(c.cfg.Retention / time.Second), WallUTC: utc(wall), CutoffUTC: utc(cutoff),
		PreviousCutoffUTC: utc(c.cutoff), Bound: bound}
	if err := c.opt.Record(ctx, r); err != nil {
		c.resync, c.resyncMono = true, m
		return fmt.Errorf("netretain: move not recorded, so not made: %w", err)
	}
	// The record is the move: from here the consumer is at to, whether or
	// not the cursor saves now. A cursor left behind only keeps more, and
	// the next Tick, or the next Start from this record, saves it.
	c.cursor, c.cutoff, c.saved = to, cutoff, false
	c.base, c.baseMono, c.afterStart = cutoff, m, false
	c.saveCursor(ctx, 0)
	return nil
}

// resyncRecord reads the latest record after a Record error. A record that
// continues the chain from the consumer's cursor is the move that reported
// the error and committed anyway: the consumer is then at its to_seq, its
// bound based on its cutoff from the failed move's monotonic time.
func (c *Consumer) resyncRecord(ctx context.Context) error {
	last, err := c.opt.Latest(ctx)
	if err != nil {
		return fmt.Errorf("netretain: re-reading the latest record: %w", err)
	}
	if last != nil && last.Stream == string(c.stream) && last.Bound != audit.BoundCreated &&
		c5.Seq(last.FromSeq) == c.cursor && c5.Seq(last.ToSeq) > c.cursor {
		cutoff, err := time.Parse(time.RFC3339Nano, last.CutoffUTC)
		if err != nil {
			return fmt.Errorf("netretain: the latest record's cutoff: %w", err)
		}
		c.cursor, c.cutoff, c.saved = c5.Seq(last.ToSeq), cutoff, false
		c.base, c.baseMono, c.afterStart = cutoff, c.resyncMono, false
	}
	c.resync = false
	return nil
}

// Status is what the node's status shows of the consumer.
type Status struct {
	Cursor c5.Seq
	// CursorSaved is false while the store's cursor is behind Cursor.
	CursorSaved bool
	// Cutoff is the last recorded cutoff, and WallCutoff the wall time less
	// the retention at the last evaluation: the two cutoffs D5-c5-0.9
	// section 3 has status show, zero before the first evaluation.
	Cutoff, WallCutoff time.Time
	// Lag is how far the monotonic bound was behind WallCutoff at the last
	// evaluation, 0 when it was not: the gap that downtime, a forward
	// clock correction or a cut to the retention leaves, which no move
	// closes, since the bound advances only with the monotonic clock (D3's
	// R1 on #559). It is not WallCutoff less Cutoff, which also grows
	// while no alert is old enough to pass.
	Lag time.Duration
	// Unrecorded is set when Start found the store's cursor past the latest
	// record, whose to_seq is UnrecordedTo: alerts from there to the
	// store's cursor were passed with no record.
	Unrecorded   bool
	UnrecordedTo c5.Seq
}

// Status returns the consumer's state.
func (c *Consumer) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	var lag time.Duration
	if c.monoCut.Before(c.wallCut) {
		lag = c.wallCut.Sub(c.monoCut)
	}
	return Status{Cursor: c.cursor, CursorSaved: c.saved, Cutoff: c.cutoff, WallCutoff: c.wallCut, Lag: lag,
		Unrecorded: c.jumped, UnrecordedTo: c.jumpedFrom}
}

// savedCursor is the store's cursor of ConsumerID, 0 if none.
func (c *Consumer) savedCursor(ctx context.Context) (c5.Seq, error) {
	cs, err := c.opt.Store.LoadCursors(ctx, c.stream)
	if err != nil {
		return 0, err
	}
	for _, cur := range cs {
		if cur.Consumer == ConsumerID {
			return cur.Through, nil
		}
	}
	return 0, nil
}

// saveCursor saves the cursor when the store's (have, if known) is behind
// it, and notes whether it is saved. A failure leaves it unsaved for the
// next Tick.
func (c *Consumer) saveCursor(ctx context.Context, have c5.Seq) {
	if have != 0 && have >= c.cursor {
		c.saved = true
		return
	}
	err := c.opt.Store.SaveCursor(ctx, c5.Cursor{Consumer: ConsumerID, Stream: c.stream, Through: c.cursor})
	c.saved = err == nil
}

// Latest returns the latest store.retention_moved record of sensorID's
// alert stream among recs, in seq order, or nil.
func Latest(recs []*audit.Record, sensorID string) *audit.Retention {
	stream := audit.AlertStreamPrefix + sensorID
	for i := len(recs) - 1; i >= 0; i-- {
		if r := recs[i]; r.Action == audit.ActionStoreRetentionMoved && r.Retention != nil && r.Retention.Stream == stream {
			return r.Retention
		}
	}
	return nil
}

func latest(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func utc(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
