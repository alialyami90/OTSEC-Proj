package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Capture is a native capture records came from: a whole SER report, one
// datagram, one pushed file. The store keeps each capture once, keyed by its
// SHA-256, and deletes it in the prune step that removes the last record
// referring to it, never before (EP-6).
type Capture struct {
	SHA256 string // lowercase hex of SHA-256(Bytes)
	Bytes  []byte
}

// Validate checks that SHA256 is the digest of Bytes.
func (c Capture) Validate() error {
	sum := sha256.Sum256(c.Bytes)
	if c.SHA256 != hex.EncodeToString(sum[:]) {
		return errf(CodeInvalid, nil, "capture digest %q does not match its %d bytes", c.SHA256, len(c.Bytes))
	}
	return nil
}

// EvidenceRef is the reference to a stored capture that C4 carries in
// native.evidence.ref: "sha256:<hex>". It names content, not a row or a file,
// so it stays valid across vacuum, restore and upgrade.
func EvidenceRef(sha string) string { return "sha256:" + sha }

// Record is what a module hands to the store. The store assigns its Key.
type Record struct {
	Stream StreamID
	Class  StreamClass
	// Event is the C4-encoded event as the producer built it: it passes
	// C4's ValidatePending, so id.seq is 0. In the commit transaction the
	// store writes the assigned seq into id, so every stored event carries
	// its full ID and passes C4's Validate before any reader sees it. Native
	// bytes and native time verbatim plus the normalized form commit
	// together and are pruned together (ADR-0004 item 2, EP-6).
	//
	// For class audit, Event is instead a pending C8 record (C8's
	// ValidatePending accepts it). The store seals it with SealAudit in the
	// commit transaction and keeps the sealed bytes exactly (C5-A3-1).
	Event []byte
	// Capture is the native capture the record came from, if any. Records
	// of one read share one Capture; the store writes it once.
	Capture *Capture
	// SourceCursor, if set, is the device-side position this record reaches
	// (for example the last SER row read). It is committed in the same
	// transaction, so a device cursor never runs ahead of the stored events.
	SourceCursor []byte
}

// Validate checks a record before it is queued.
func (r Record) Validate() error {
	if !r.Stream.Valid() {
		return errf(CodeInvalid, nil, "record stream %q is not a valid stream token", r.Stream)
	}
	if _, err := ActionFor(r.Class); err != nil {
		return err
	}
	if len(r.Event) == 0 {
		return errf(CodeInvalid, nil, "record for %s has no event bytes", r.Stream)
	}
	if r.Capture != nil {
		return r.Capture.Validate()
	}
	return nil
}

// Sync is the durability level a commit returned at.
type Sync int

const (
	SyncUnknown Sync = iota
	SyncOff
	SyncNormal
	// SyncFull: the commit returned only after the WAL was flushed to the
	// device (FlushFileBuffers on Windows, fsync on Linux). A6 E-02 and H-14
	// part 1 show NORMAL acknowledges before the flush; only FULL counts.
	SyncFull
)

// Commit describes one committed batch.
type Commit struct {
	Node     NodeID
	Stream   StreamID
	FirstSeq Seq
	Count    int
	Sync     Sync
	At       time.Time
}

// Committer is implemented by a store (Phase 2, SQLite). Only Log calls it.
type Committer interface {
	// CommitBatch writes every record in one transaction, in order, assigns
	// consecutive seqs starting at the stream's next seq, and returns only
	// after the transaction has committed at the reported Sync. For class
	// audit it seals the records with SealAudit inside the transaction.
	//
	// It may refuse a batch, having written nothing, with an *Error whose
	// Code is CodeQuotaReached (the class is at quota and its action refuses)
	// or CodeInvalid (for example a pending audit record SealAudit rejects).
	// The Log fails that batch's appends with the error and keeps running.
	// Any other error means the durability of the batch is unknown, and the
	// Log stops.
	CommitBatch(ctx context.Context, stream StreamID, recs []Record) (Commit, error)
}

// Receipt is proof that a record is durably committed. It is the only value
// that may release an acknowledgement to a source (a RELP ack, a device-side
// cursor advance outside the store, a "stored" status). Only Log creates
// receipts, and only after the commit that holds the record has returned at
// SyncFull. The interface is sealed: code outside this package cannot
// implement it, and a nil or embedded-nil Receipt panics on use.
type Receipt interface {
	Key() Key
	CommittedAt() time.Time
	sealed()
}

type receipt struct {
	key Key
	at  time.Time
}

func (r receipt) Key() Key               { return r.key }
func (r receipt) CommittedAt() time.Time { return r.at }
func (receipt) sealed()                  {}

// GroupOptions sets group commit. Group commit is required: W-1 measured 92
// events/s with one event per commit on an NTFS virtual disk, 676 events/s
// with 100, and E-A5-6 about 10.6 KB written per event against 1.05 KB.
type GroupOptions struct {
	// MaxEvents commits a group as soon as it holds this many records.
	MaxEvents int
	// MaxWait is the longest a record waits for others before its group
	// commits. It bounds the latency group commit adds.
	MaxWait time.Duration
}

// DefaultGroup is the proposed default (A5, not yet measured on site
// hardware): 100 events or 100 ms, whichever comes first.
var DefaultGroup = GroupOptions{MaxEvents: 100, MaxWait: 100 * time.Millisecond}

// Validate checks group options. One event per commit is not allowed.
func (o GroupOptions) Validate() error {
	if o.MaxEvents < 2 || o.MaxEvents > 10000 {
		return errf(CodeInvalid, nil, "group MaxEvents %d not in [2, 10000]", o.MaxEvents)
	}
	if o.MaxWait <= 0 || o.MaxWait > time.Second {
		return errf(CodeInvalid, nil, "group MaxWait %s not in (0, 1s]", o.MaxWait)
	}
	return nil
}

// Log is the only way to append to a store. It groups records per stream,
// hands each group to the Committer, checks the returned Commit, and only then
// releases a Receipt to each waiting caller. After any commit failure it
// stops: every later Append fails with CodeLogStopped until the process
// restarts and startup recovery runs, because after a failed flush the state
// of the file is unknown and retrying could acknowledge lost data.
type Log struct {
	c    Committer
	opt  GroupOptions
	node NodeID

	mu      sync.Mutex
	pending map[StreamID]*group
	tail    map[StreamID]chan struct{} // done of the stream's newest group
	last    map[StreamID]Seq
	stopped error
}

type group struct {
	stream StreamID
	recs   []Record
	timer  *time.Timer
	prev   chan struct{} // the previous group of this stream; commit waits for it
	done   chan struct{}
	keys   []Key
	at     time.Time
	err    error
}

// NewLog returns a Log over c for node. last holds each stream's last
// committed seq as read at startup (absent: unknown, and the first commit
// sets it); it lets the Log reject a Commit that leaves a gap or overlaps.
func NewLog(c Committer, node NodeID, opt GroupOptions, last map[StreamID]Seq) (*Log, error) {
	if err := opt.Validate(); err != nil {
		return nil, err
	}
	if !node.Valid() {
		return nil, errf(CodeInvalid, nil, "node ID %q is not a lowercase DNS label", node)
	}
	l := &Log{c: c, opt: opt, node: node, pending: map[StreamID]*group{}, tail: map[StreamID]chan struct{}{}, last: map[StreamID]Seq{}}
	for s, q := range last {
		l.last[s] = q
	}
	return l, nil
}

// Append queues rec and blocks until the group holding it has committed at
// SyncFull, then returns its Receipt. If ctx ends first, Append returns
// ctx.Err() and no Receipt; the record may still commit, so the source must
// not be acknowledged and will re-send (at-least-once).
func (l *Log) Append(ctx context.Context, rec Record) (Receipt, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.stopped != nil {
		l.mu.Unlock()
		return nil, errf(CodeLogStopped, l.stopped, "log stopped")
	}
	g := l.pending[rec.Stream]
	if g == nil {
		g = &group{stream: rec.Stream, prev: l.tail[rec.Stream], done: make(chan struct{})}
		l.pending[rec.Stream] = g
		l.tail[rec.Stream] = g.done
		g.timer = time.AfterFunc(l.opt.MaxWait, func() { l.flush(g) })
	}
	i := len(g.recs)
	g.recs = append(g.recs, rec)
	full := len(g.recs) >= l.opt.MaxEvents
	l.mu.Unlock()
	if full {
		l.flush(g)
	}
	select {
	case <-g.done:
		if g.err != nil {
			return nil, g.err
		}
		return receipt{key: g.keys[i], at: g.at}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// MaxBatch is the largest AppendBatch.
const MaxBatch = 10000

// AppendBatch commits recs, all of one stream, in one transaction, after any
// records of that stream already waiting in a group, and returns one Receipt
// per record in order. It is for producers that already hold a batch, such
// as one SER read: the whole read, its capture and its device cursor commit
// together or not at all. ctx is checked before the batch is queued; once
// queued, the call returns only when the commit has returned.
func (l *Log) AppendBatch(ctx context.Context, recs []Record) ([]Receipt, error) {
	if len(recs) == 0 || len(recs) > MaxBatch {
		return nil, errf(CodeInvalid, nil, "batch of %d records, want 1 to %d", len(recs), MaxBatch)
	}
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if r.Stream != recs[0].Stream {
			return nil, errf(CodeInvalid, nil, "batch mixes streams %s and %s", recs[0].Stream, r.Stream)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stream := recs[0].Stream
	l.mu.Lock()
	if l.stopped != nil {
		l.mu.Unlock()
		return nil, errf(CodeLogStopped, l.stopped, "log stopped")
	}
	waiting := l.pending[stream]
	if waiting != nil {
		delete(l.pending, stream)
		waiting.timer.Stop()
	}
	g := &group{stream: stream, recs: recs, prev: l.tail[stream], done: make(chan struct{})}
	l.tail[stream] = g.done
	l.mu.Unlock()
	if waiting != nil {
		go l.run(waiting)
	}
	l.run(g)
	if g.err != nil {
		return nil, g.err
	}
	out := make([]Receipt, len(recs))
	for i := range recs {
		out[i] = receipt{key: g.keys[i], at: g.at}
	}
	return out, nil
}

// flush commits g once, whichever of the timer and a full group gets here
// first. Groups of one stream commit one at a time, in the order they were
// opened, so seqs follow append order.
func (l *Log) flush(g *group) {
	l.mu.Lock()
	if l.pending[g.stream] != g {
		l.mu.Unlock()
		return // already flushed
	}
	delete(l.pending, g.stream)
	g.timer.Stop()
	l.mu.Unlock()
	l.run(g)
}

func (l *Log) run(g *group) {
	l.commitGroup(g)
	close(g.done)
}

func (l *Log) commitGroup(g *group) {
	if g.prev != nil {
		<-g.prev
	}
	l.mu.Lock()
	if l.stopped != nil {
		g.err = errf(CodeLogStopped, l.stopped, "log stopped")
		l.mu.Unlock()
		return
	}
	prev, known := l.last[g.stream]
	l.mu.Unlock()

	c, err := l.c.CommitBatch(context.Background(), g.stream, g.recs)
	if refused(err) {
		g.err = err // nothing was written; the Log keeps running
		return
	}
	switch {
	case err != nil:
		err = errf(CodeCommitFailed, err, "stream %s, %d records", g.stream, len(g.recs))
	case c.Sync != SyncFull:
		err = errf(CodeCommitNotDurable, nil, "stream %s committed at sync level %d, FULL required", g.stream, c.Sync)
	case c.Stream != g.stream || c.Count != len(g.recs) || c.Node != l.node:
		err = errf(CodeCommitMismatch, nil, "commit %s:%s count %d for %d records of %s:%s", c.Node, c.Stream, c.Count, len(g.recs), l.node, g.stream)
	case c.FirstSeq == 0 || (known && c.FirstSeq != prev+1):
		err = errf(CodeCommitMismatch, nil, "stream %s: first seq %d after %d", g.stream, c.FirstSeq, prev)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		g.err = err
		l.stopped = err
		return
	}
	g.keys = make([]Key, len(g.recs))
	for i := range g.recs {
		g.keys[i] = Key{NodeID: l.node, Stream: g.stream, Seq: c.FirstSeq + Seq(i)}
	}
	g.at = c.At
	l.last[g.stream] = c.FirstSeq + Seq(c.Count) - 1
}

// refused reports whether a CommitBatch error is a refusal that wrote
// nothing.
func refused(err error) bool {
	return errors.Is(err, &Error{Code: CodeQuotaReached}) || errors.Is(err, &Error{Code: CodeInvalid})
}

// Stopped reports the error that stopped the Log, or nil.
func (l *Log) Stopped() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopped
}
