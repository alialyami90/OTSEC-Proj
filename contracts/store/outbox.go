package store

import (
	"context"
	"time"
)

// Stored is a committed event as the outbox returns it.
type Stored struct {
	Key          Key
	Class        StreamClass
	Event        []byte
	EvidenceRef  string // EvidenceRef of the record's capture, "" if none
	SourceCursor []byte
	CommittedAt  time.Time
}

// Outbox reads committed events. It never returns an event whose commit has
// not returned, and returns events of a stream in seq order with no gaps
// except below the stream's prune point.
type Outbox interface {
	// Read returns up to max events of stream with seq > after. If after is
	// below the stream's prune point, it returns the first retained events
	// with no error; the caller sees the jump in seq and reports the skipped
	// range (C6: forward.unreachable).
	Read(ctx context.Context, stream StreamID, after Seq, max int) ([]Stored, error)
	// ReadCapture returns the capture an EvidenceRef names. It is held at
	// least as long as any record that refers to it.
	ReadCapture(ctx context.Context, ref string) (Capture, error)
	// ChainAnchor returns the link of the last record pruned from the audit
	// stream, or GenesisLink if none was. The prune step that
	// removes audit records writes it in the same transaction, so the
	// retained chain always verifies from it (C5-A3-2). It is read-only.
	// It fails with CodeInvalid for a stream that is not the audit stream.
	ChainAnchor(ctx context.Context, stream StreamID) (ChainLink, error)
}

// CommitIndex answers position questions about committed events.
type CommitIndex interface {
	// LastCommitted is the highest committed seq of stream, 0 if none.
	LastCommitted(ctx context.Context, stream StreamID) (Seq, error)
	// LastCommittedBy is the highest seq of stream committed at or before t,
	// 0 if none. Best-effort replay windows are measured with it.
	LastCommittedBy(ctx context.Context, stream StreamID, t time.Time) (Seq, error)
	// FirstRetained is the lowest seq of stream still stored, 0 if none.
	FirstRetained(ctx context.Context, stream StreamID) (Seq, error)
}

// ConsumerID names a delivery target: for Syslog, the C6 target name; for
// site-to-central, the central server. Delivery uses the same strings as the
// C6 target class.
type ConsumerID string

// Delivery says whether a consumer holds back pruning (ADR-0004 item 6).
type Delivery string

const (
	// Required: events are pruned only after this consumer confirmed them.
	// Only a consumer whose acknowledgement cannot be forged may be
	// required: for Syslog that is a C6 target with transport relp-tls
	// (plain RELP acknowledgements can be forged) whose commissioning check
	// showed that its collector acknowledges only after a durable write (C6
	// Target.DurableAck, A6 V-S6). Pruning trusts the acknowledgement only
	// because of that check: E-A4-03 lost 1,471 of 1,500 acknowledged
	// messages with rsyslog's default queues.
	Required Delivery = "required"
	// BestEffort: the consumer cannot confirm delivery (for example plain
	// RFC 5425). Events older than its replay window are prunable for it.
	BestEffort Delivery = "best-effort"
)

// Consumer is one delivery target of one stream.
type Consumer struct {
	ID       ConsumerID
	Stream   StreamID
	Delivery Delivery
	// ReplayWindow is how long a best-effort consumer's events are kept for
	// replay after reconnection. Zero for required consumers.
	ReplayWindow time.Duration
}

// Validate checks one consumer.
func (c Consumer) Validate() error {
	if c.ID == "" || c.Stream == "" {
		return errf(CodeInvalid, nil, "consumer needs an ID and a stream")
	}
	switch c.Delivery {
	case Required:
		if c.ReplayWindow != 0 {
			return errf(CodeInvalid, nil, "required consumer %s has a replay window", c.ID)
		}
	case BestEffort:
		if c.ReplayWindow <= 0 {
			return errf(CodeInvalid, nil, "best-effort consumer %s needs a replay window", c.ID)
		}
	default:
		return errf(CodeInvalid, nil, "consumer %s: unknown delivery %q", c.ID, c.Delivery)
	}
	return nil
}

// Cursor is the position through which a consumer has confirmed delivery of
// a stream. For a best-effort consumer it is only the position sent: it tells
// the forwarder where to resume and never makes anything prunable.
type Cursor struct {
	Consumer ConsumerID
	Stream   StreamID
	Through  Seq
}

// CursorStore keeps consumer cursors durably, in the same database as the
// stream.
type CursorStore interface {
	// SaveCursor returns only after the cursor has committed at SyncFull.
	// It fails with CodeCursorRegress if c.Through is below the persisted
	// cursor, and with CodeCursorAhead if c.Through is above the stream's
	// last committed seq.
	SaveCursor(ctx context.Context, c Cursor) error
	// LoadCursors reads the persisted cursors of stream from the database on
	// every call. It never answers from a cache, so a boundary computed after
	// a crash sees exactly what was committed before it (R-A5-5).
	LoadCursors(ctx context.Context, stream StreamID) ([]Cursor, error)
}

// Boundary is the highest seq of one stream that may be pruned. It is sealed:
// the only way to get one is ComputeBoundary, which derives it from persisted
// cursors at the time of the call. A Pruner accepts nothing else, so a prune
// cannot take a position held in memory, a step counter, or "the oldest
// half" (R-A5-5: an interrupted recovery that recomputes such a target
// prunes twice). A Boundary is not serializable and does not outlive the
// process.
type Boundary interface {
	Stream() StreamID
	Through() Seq
	sealedBoundary()
}

type boundary struct {
	stream  StreamID
	through Seq
}

func (b boundary) Stream() StreamID { return b.stream }
func (b boundary) Through() Seq     { return b.through }
func (boundary) sealedBoundary()    {}

// ComputeBoundary reads the persisted cursors of stream and returns the
// highest seq every consumer allows to prune:
//   - a required consumer allows up to its persisted cursor (none: 0);
//   - a best-effort consumer allows up to the last seq committed before now
//     minus its replay window, whatever its cursor says: "sent" is not
//     "delivered", and a reconnect must still find the window to replay (A4
//     review of C5, change 1). The window is measured on the node's clock,
//     so a forward clock step shortens it; C6's window is by time only, as
//     ADR-0004 item 6 says;
//   - the boundary is the lowest of these, and never above the last
//     committed seq.
//
// For class audit only required consumers count: a replay window never
// makes an audit record prunable, because that would delete it with no
// confirmed delivery (C5-A3-2, AP-17).
//
// A stream with no consumers that count fails with CodeNoConsumers: nothing
// confirms its events, and the site is the system of record.
func ComputeBoundary(ctx context.Context, cs CursorStore, idx CommitIndex, consumers []Consumer, stream StreamID, class StreamClass, now time.Time) (Boundary, error) {
	if _, err := ActionFor(class); err != nil {
		return nil, err
	}
	var mine []Consumer
	for _, c := range consumers {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if c.Stream == stream && (class != ClassAudit || c.Delivery == Required) {
			mine = append(mine, c)
		}
	}
	if len(mine) == 0 {
		return nil, errf(CodeNoConsumers, nil, "stream %s (%s)", stream, class)
	}
	persisted, err := cs.LoadCursors(ctx, stream)
	if err != nil {
		return nil, err
	}
	at := map[ConsumerID]Seq{}
	for _, p := range persisted {
		if p.Stream != stream {
			return nil, errf(CodeInvalid, nil, "LoadCursors(%s) returned a cursor of %s", stream, p.Stream)
		}
		at[p.Consumer] = p.Through
	}
	last, err := idx.LastCommitted(ctx, stream)
	if err != nil {
		return nil, err
	}
	through := last
	for _, c := range mine {
		allow := at[c.ID]
		if c.Delivery == BestEffort {
			aged, err := idx.LastCommittedBy(ctx, stream, now.Add(-c.ReplayWindow))
			if err != nil {
				return nil, err
			}
			allow = aged
		}
		through = min(through, allow)
	}
	return boundary{stream: stream, through: through}, nil
}

// Pruner deletes confirmed events.
type Pruner interface {
	// PruneStep deletes, in one transaction committed at SyncFull, the
	// oldest at most max events of b.Stream() with seq <= b.Through() that
	// are not held (Holder, 0.4). The boundary may pass a held seq: the
	// held record stays, still counts in its class's usage, and later
	// unheld seqs are pruned in order around it. It
	// deletes each event's native bytes and normalized form together, and
	// returns how many it deleted (0 when nothing at or below the boundary
	// is left). A capture no retained record refers to any more is deleted
	// in the same transaction. For the audit stream, the same transaction
	// also writes the ChainLink of the last record it deletes as the
	// stream's chain anchor. Small steps matter: a single large delete can need more WAL
	// space than a full disk has (E-A5-3).
	PruneStep(ctx context.Context, b Boundary, max int) (int, error)
}
