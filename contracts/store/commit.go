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
	//
	// For class configuration (0.4), Event is a typed document (a C9
	// snapshot or difference, or a C10 baseline) that the store's injected
	// DocumentValidator accepts. The store keeps its bytes exactly, with no
	// seq written in, so a digest over the stored bytes is stable.
	Event []byte
	// Capture is the native capture the record came from, if any. Records
	// of one read share one Capture; the store writes it once.
	Capture *Capture
	// SourceCursor, if set, is the device-side position this record reaches
	// (for example the last SER row read). It is committed in the same
	// transaction, so a device cursor never runs ahead of the stored events.
	SourceCursor []byte
	// Holds (0.4, configuration class only) commit in the same transaction
	// as the record, so no prune step can fall between a snapshot with an
	// unapproved difference and its hold (B3 on #246). Each names this
	// record (empty Stream, Seq 0) or an earlier one of the same database.
	Holds []Hold
}

// Bytes is what the record adds to a commit: its event and its capture.
func (r Record) Bytes() int64 {
	n := int64(len(r.Event))
	if r.Capture != nil {
		n += int64(len(r.Capture.Bytes))
	}
	return n
}

// DocumentValidator checks a configuration-class record before it is
// stored (0.4). It sees the capture as well as the document, so a C9
// snapshot can be bound to the transcript it names (B2 on #246). The
// writer injects it, so C5 imports neither C9 nor C10.
type DocumentValidator func(document []byte, capture *Capture) error

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
	for _, h := range r.Holds {
		if err := h.Reason.Validate(); err != nil {
			return err
		}
		if h.Stream != "" && !h.Stream.Valid() {
			return errf(CodeInvalid, nil, "hold names stream %q, not a valid stream token", h.Stream)
		}
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
	// Code is CodeQuotaReached (the class is at quota and its action refuses),
	// CodeInvalid (for example a pending audit record SealAudit rejects),
	// or, from 0.4, CodeRecordTooLarge or CodeNotHoldable.
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
	// MaxCommitBytes (0.4, D4-9) bounds one commit's payload, events plus
	// captures: a group commits before a record would take it past this.
	// It bounds groups, not single records: a record over it commits alone
	// if its class's MaxRecordBytes allows it. 0 means
	// DefaultMaxCommitBytes. The recovery reserve is sized from it
	// (RecoveryReserveFor).
	MaxCommitBytes int64
	// MaxCommitRecords (0.5, D4-14) bounds the records in one commit the
	// way MaxCommitBytes bounds its bytes: an AppendBatch of more records
	// than this is refused with CodeRecordTooLarge and nothing is queued, so
	// the producer splits it. Groups already close at MaxEvents, so it is at
	// least MaxEvents. 0 means MaxEvents. The recovery reserve is sized
	// from it (RecoveryReserveFor), because each row costs WAL beyond its
	// payload (RowWALBytes).
	MaxCommitRecords int
}

// CommitRecords is the effective MaxCommitRecords.
func (o GroupOptions) CommitRecords() int {
	if o.MaxCommitRecords == 0 {
		return o.MaxEvents
	}
	return o.MaxCommitRecords
}

// DefaultGroup is the proposed default (A5, not yet measured on site
// hardware): 100 events or 100 ms, whichever comes first.
var DefaultGroup = GroupOptions{MaxEvents: 100, MaxWait: 100 * time.Millisecond}

// DefaultMaxCommitBytes is the commit cap of an event database (D4-9).
const DefaultMaxCommitBytes = 1 << 20

// Validate checks group options. One event per commit is not allowed.
func (o GroupOptions) Validate() error {
	if o.MaxEvents < 2 || o.MaxEvents > 10000 {
		return errf(CodeInvalid, nil, "group MaxEvents %d not in [2, 10000]", o.MaxEvents)
	}
	if o.MaxWait <= 0 || o.MaxWait > time.Second {
		return errf(CodeInvalid, nil, "group MaxWait %s not in (0, 1s]", o.MaxWait)
	}
	if o.MaxCommitBytes != 0 && o.MaxCommitBytes < MinRecordBytes {
		return errf(CodeInvalid, nil, "group MaxCommitBytes %d below %d", o.MaxCommitBytes, MinRecordBytes)
	}
	if o.MaxCommitRecords != 0 && (o.MaxCommitRecords < o.MaxEvents || o.MaxCommitRecords > MaxBatch) {
		return errf(CodeInvalid, nil, "group MaxCommitRecords %d not in [MaxEvents %d, %d]", o.MaxCommitRecords, o.MaxEvents, MaxBatch)
	}
	return nil
}

// CommitBytes is the effective MaxCommitBytes.
func (o GroupOptions) CommitBytes() int64 {
	if o.MaxCommitBytes == 0 {
		return DefaultMaxCommitBytes
	}
	return o.MaxCommitBytes
}

// LargestCommit is the most payload one commit of database d can carry
// under opt: the commit cap, or a single record at the largest class cap
// if that is larger. The recovery reserve covers it (RecoveryReserveFor).
func LargestCommit(d Database, opt GroupOptions) int64 {
	n := opt.CommitBytes()
	for _, q := range d.Quotas {
		n = max(n, q.MaxRecordBytes)
	}
	return n
}

// LargestCommitRecords (0.5) is the most records one commit of database d
// can carry under opt: the commit record cap, or one for a database that
// holds only the configuration class, whose commit is one record and the
// holds it takes (at most MaxHoldsPerRecord small rows, inside the fixed
// term of CommitWALBytes).
func LargestCommitRecords(d Database, opt GroupOptions) int64 {
	if len(d.Classes) > 0 {
		only := true
		for _, c := range d.Classes {
			only = only && c == ClassConfiguration
		}
		if only {
			return 1
		}
	}
	return int64(opt.CommitRecords())
}

// RowWALBytes (0.5, D4-14) is the WAL each record of a commit may write
// beyond its payload: a row's cell, its index entries, and, on a rowid
// table with 4 KiB pages, the page it takes alone when it is too big to
// share one (an event just over half a page), which is the worst case.
// Measured on the real store by B6's event-size sweep (#280, 100 B to
// 64 KiB, 128 events a commit): the worst excess over 1.1 × payload is
// 2,051 bytes a row, at events of 2 KB (simulated, Linux). 3 KiB is that
// plus about 50%. It does not depend on the payload.
const RowWALBytes = 3 << 10

// CommitWALBytes is the WAL one commit of payload bytes and records rows may
// write: 1.1 × payload, a fixed 64 KiB, and RowWALBytes a record. Measured
// on one record after a TRUNCATE checkpoint with 4 KiB pages, 128 KiB to
// 768 KiB (B5, modernc SQLite; B6, SQLite through Python, another schema): a
// fixed 21 to 34 KB plus 1.0 to 1.03 × the payload (simulated, #246). A
// ratio alone fails at small caps, so the rule is payload plus a constant,
// and since 0.5 a term a record, because small and half-page events cost
// more WAL than their payload (D4-14).
func CommitWALBytes(payload, records int64) int64 {
	return payload + payload/10 + 64<<10 + records*RowWALBytes
}

// RecoveryReserveFor is the smallest recovery reserve of a database whose
// WAL holds at most walBound between checkpoints when every commit is
// small, and whose largest commit carries largestCommit payload bytes in
// at most records rows (0.5). A store found full at start may hold
// un-checkpointed frames: checkpointing them can extend the database by up
// to walBound plus the largest commit's WAL, and recovery's own small
// commits (prune and compaction steps) need up to walBound more.
func RecoveryReserveFor(walBound, largestCommit, records int64) int64 {
	return 2*walBound + CommitWALBytes(largestCommit, records)
}

// DiskBytesPerQuotaByte (0.5, D4-14) bounds the file's size against what the
// quota counts: once checkpointed, a database's file grows by at most this
// many bytes for each byte its class quotas count (ClassBytes). The quota
// counts event, capture and cursor bytes, not the pages, indexes and cell
// slack around them. Measured on the real store by B6's event-size sweep
// (#280): at most 2.02 at events of 2 KB on a rowid table, where two events
// do not fit one page (simulated, Linux). Volume sizing is therefore
//
//	sum of class quotas × DiskBytesPerQuotaByte
//	  + each database's RecoveryReserveBytes and LastResortReserveBytes
//
// and no volume figure may come from the raw sum of quotas.
const DiskBytesPerQuotaByte = 2.5

// Log is the only way to append to a store. It groups records per stream,
// hands each group to the Committer, checks the returned Commit, and only then
// releases a Receipt to each waiting caller. After any commit failure it
// stops: every later Append fails with CodeLogStopped until the process
// restarts and startup recovery runs, because after a failed flush the state
// of the file is unknown and retrying could acknowledge lost data.
type Log struct {
	c       Committer
	opt     GroupOptions
	node    NodeID
	classes map[StreamID]StreamClass
	caps    map[StreamClass]int64 // Quota.MaxRecordBytes, where set

	mu      sync.Mutex
	pending map[StreamID]*group
	tail    map[StreamID]chan struct{} // done of the stream's newest group
	last    map[StreamID]Seq
	stopped error
}

type group struct {
	stream StreamID
	recs   []Record
	bytes  int64
	timer  *time.Timer
	prev   chan struct{} // the previous group of this stream; commit waits for it
	done   chan struct{}
	keys   []Key
	at     time.Time
	err    error
}

// NewLog returns a Log over c for node. classes maps each stream the Log may
// write to its class (Layout.StreamClasses, or the part of it for c's
// database); the Log refuses a record for any other stream, or whose class
// differs from its stream's. last holds each stream's last committed seq as
// read at startup (absent: unknown, and the first commit sets it); it lets
// the Log reject a Commit that leaves a gap or overlaps.
func NewLog(c Committer, node NodeID, classes map[StreamID]StreamClass, opt GroupOptions, last map[StreamID]Seq) (*Log, error) {
	return newLog(c, node, classes, opt, last, nil)
}

// NewLogFor returns a Log over c for database d's streams (0.4). Unlike
// NewLog it takes each class's MaxRecordBytes from d's quotas, so it is
// the constructor for a database with a configuration class.
func NewLogFor(c Committer, node NodeID, d Database, opt GroupOptions, last map[StreamID]Seq) (*Log, error) {
	classes := map[StreamID]StreamClass{}
	for _, s := range d.Streams {
		classes[s.ID] = s.Class
	}
	caps := map[StreamClass]int64{}
	for _, q := range d.Quotas {
		if err := q.Validate(); err != nil {
			return nil, err
		}
		if q.MaxRecordBytes > 0 {
			caps[q.Class] = q.MaxRecordBytes
		}
	}
	return newLog(c, node, classes, opt, last, caps)
}

func newLog(c Committer, node NodeID, classes map[StreamID]StreamClass, opt GroupOptions, last map[StreamID]Seq, caps map[StreamClass]int64) (*Log, error) {
	if err := opt.Validate(); err != nil {
		return nil, err
	}
	if !node.Valid() {
		return nil, errf(CodeInvalid, nil, "node ID %q is not a lowercase DNS label", node)
	}
	if len(classes) == 0 {
		return nil, errf(CodeInvalid, nil, "log has no streams")
	}
	l := &Log{c: c, opt: opt, node: node, classes: map[StreamID]StreamClass{}, caps: map[StreamClass]int64{}, pending: map[StreamID]*group{}, tail: map[StreamID]chan struct{}{}, last: map[StreamID]Seq{}}
	audit := 0
	for s, class := range classes {
		if !s.Valid() {
			return nil, errf(CodeInvalid, nil, "stream %q is not a valid stream token", s)
		}
		if _, err := ActionFor(class); err != nil {
			return nil, err
		}
		if class == ClassConfiguration && caps[class] == 0 {
			// Its record cap is in its quota (0.4).
			return nil, errf(CodeInvalid, nil, "stream %s is configuration, with no record cap: use NewLogFor with its database", s)
		}
		l.classes[s] = class
		if class == ClassAudit {
			audit++
		}
	}
	if audit > 1 {
		// The C8 chain is one per node, so "the Log's audit stream" must be
		// unambiguous (A6 re-check of C5).
		return nil, errf(CodeInvalid, nil, "log has %d audit streams, at most one allowed", audit)
	}
	for s, q := range last {
		l.last[s] = q
	}
	for class, n := range caps {
		l.caps[class] = n
	}
	return l, nil
}

// Append queues rec and blocks until the group holding it has committed at
// SyncFull, then returns its Receipt. If ctx ends first, Append returns
// ctx.Err() and no Receipt; the record may still commit, so the source must
// not be acknowledged and will re-send (at-least-once).
func (l *Log) Append(ctx context.Context, rec Record) (Receipt, error) {
	if err := l.check(rec); err != nil {
		return nil, err
	}
	size := rec.Bytes()
	if rec.Class == ClassConfiguration || size > l.opt.CommitBytes() {
		// A configuration record, or one over the commit cap that its
		// class's cap allows, commits alone (0.4, D4-9).
		g, err := l.enqueue(rec.Stream, []Record{rec})
		if err != nil {
			return nil, err
		}
		return l.wait(ctx, g, 0)
	}
	l.mu.Lock()
	if l.stopped != nil {
		l.mu.Unlock()
		return nil, errf(CodeLogStopped, l.stopped, "log stopped")
	}
	g := l.pending[rec.Stream]
	if g != nil && g.bytes+size > l.opt.CommitBytes() {
		// The group commits before this record would take it past the
		// commit cap.
		delete(l.pending, rec.Stream)
		g.timer.Stop()
		go l.run(g)
		g = nil
	}
	if g == nil {
		g = &group{stream: rec.Stream, prev: l.tail[rec.Stream], done: make(chan struct{})}
		l.pending[rec.Stream] = g
		l.tail[rec.Stream] = g.done
		g.timer = time.AfterFunc(l.opt.MaxWait, func() { l.flush(g) })
	}
	i := len(g.recs)
	g.recs = append(g.recs, rec)
	g.bytes += size
	full := len(g.recs) >= l.opt.MaxEvents
	l.mu.Unlock()
	if full {
		l.flush(g)
	}
	return l.wait(ctx, g, i)
}

// wait returns the Receipt of g's record i once g has committed, or
// ctx.Err() if ctx ends first.
func (l *Log) wait(ctx context.Context, g *group, i int) (Receipt, error) {
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
//
// Since 0.4 a batch of more than one record must fit MaxCommitBytes, a
// capture shared by several records counting once, and since 0.5 hold no
// more than MaxCommitRecords records, or it is refused with
// CodeRecordTooLarge and nothing is queued: the producer splits it. A
// configuration batch holds one record.
func (l *Log) AppendBatch(ctx context.Context, recs []Record) ([]Receipt, error) {
	if len(recs) == 0 || len(recs) > MaxBatch {
		return nil, errf(CodeInvalid, nil, "batch of %d records, want 1 to %d", len(recs), MaxBatch)
	}
	var size int64
	captures := map[string]bool{}
	for _, r := range recs {
		if err := l.check(r); err != nil {
			return nil, err
		}
		if r.Stream != recs[0].Stream {
			return nil, errf(CodeInvalid, nil, "batch mixes streams %s and %s", recs[0].Stream, r.Stream)
		}
		size += int64(len(r.Event))
		if r.Capture != nil && !captures[r.Capture.SHA256] {
			captures[r.Capture.SHA256] = true
			size += int64(len(r.Capture.Bytes))
		}
	}
	if len(recs) > 1 {
		if recs[0].Class == ClassConfiguration {
			return nil, errf(CodeInvalid, nil, "configuration batch of %d records: one record per commit", len(recs))
		}
		if size > l.opt.CommitBytes() {
			return nil, errf(CodeRecordTooLarge, nil, "batch of %d records, %d bytes, over the commit cap %d", len(recs), size, l.opt.CommitBytes())
		}
		if len(recs) > l.opt.CommitRecords() {
			return nil, errf(CodeRecordTooLarge, nil, "batch of %d records, over the commit record cap %d", len(recs), l.opt.CommitRecords())
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g, err := l.enqueue(recs[0].Stream, recs)
	if err != nil {
		return nil, err
	}
	<-g.done
	if g.err != nil {
		return nil, g.err
	}
	out := make([]Receipt, len(recs))
	for i := range recs {
		out[i] = receipt{key: g.keys[i], at: g.at}
	}
	return out, nil
}

// enqueue queues recs as a group of their own, after any group of the
// stream already waiting, which it commits first, and starts its commit.
func (l *Log) enqueue(stream StreamID, recs []Record) (*group, error) {
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
	go l.run(g)
	return g, nil
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

// check validates rec and refuses a stream the Log does not write, or a class
// that is not the stream's.
func (l *Log) check(rec Record) error {
	if err := rec.Validate(); err != nil {
		return err
	}
	c, ok := l.classes[rec.Stream]
	if !ok {
		return errf(CodeInvalid, nil, "this log does not write stream %s", rec.Stream)
	}
	if rec.Class != c {
		return errf(CodeInvalid, nil, "record of class %s for stream %s, which is %s", rec.Class, rec.Stream, c)
	}
	if len(rec.Holds) > 0 && c != ClassConfiguration {
		return errf(CodeNotHoldable, nil, "record of class %s for stream %s takes holds; only configuration records may", c, rec.Stream)
	}
	if limit, ok := l.caps[c]; ok && rec.Bytes() > limit {
		return errf(CodeRecordTooLarge, nil, "record of %d bytes for stream %s, over the %s cap %d", rec.Bytes(), rec.Stream, c, limit)
	} else if !ok && rec.Bytes() > l.opt.CommitBytes() {
		return errf(CodeRecordTooLarge, nil, "record of %d bytes for stream %s, over the commit cap %d", rec.Bytes(), rec.Stream, l.opt.CommitBytes())
	}
	return nil
}

// ClassOf returns the class of stream in this Log, and false if the Log does
// not write it.
func (l *Log) ClassOf(stream StreamID) (StreamClass, bool) {
	c, ok := l.classes[stream]
	return c, ok
}

// refused reports whether a CommitBatch error is a refusal that wrote
// nothing.
func refused(err error) bool {
	for _, c := range []Code{CodeQuotaReached, CodeInvalid, CodeRecordTooLarge, CodeNotHoldable} {
		if errors.Is(err, &Error{Code: c}) {
			return true
		}
	}
	return false
}

// Stopped reports the error that stopped the Log, or nil.
func (l *Log) Stopped() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopped
}
