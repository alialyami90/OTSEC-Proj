package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// fake is an in-memory store and startup environment. It implements
// Committer, StartupEnv and RecoveryStore, records every call, and fails any
// call named in fail. It also records contract violations it can see from
// the inside: an open of the database while the reserve startup should have
// released is still in place.
type fake struct {
	mu sync.Mutex

	node     NodeID
	sync     Sync // level CommitBatch reports
	now      time.Time
	events   map[StreamID][]Stored
	next     map[StreamID]Seq
	cursors  map[StreamID]map[ConsumerID]Seq // persisted only
	captures map[string]Capture

	chain     AuditChain // seals records of class audit when set
	heads     map[StreamID]ChainLink
	anchors   map[StreamID]ChainLink
	quotaFull map[StreamID]bool

	storeExists bool
	reserves    map[Reserve]bool
	free        int64
	limit       int64
	eventSize   int64
	freePages   int
	opened      bool

	calls      []string
	fail       map[string]error
	pruneLimit int // PruneStep fails once this many steps have run (0: never)
	pruneSteps int
	violations []string
}

var errInjected = errors.New("injected failure")

func newFake() *fake {
	return &fake{
		node:      "site-a-node1",
		sync:      SyncFull,
		now:       time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC),
		events:    map[StreamID][]Stored{},
		next:      map[StreamID]Seq{},
		cursors:   map[StreamID]map[ConsumerID]Seq{},
		captures:  map[string]Capture{},
		heads:     map[StreamID]ChainLink{},
		anchors:   map[StreamID]ChainLink{},
		quotaFull: map[StreamID]bool{},
		reserves:  map[Reserve]bool{},
		free:      1 << 20,
		limit:     1 << 30,
		eventSize: 8 << 10,
		fail:      map[string]error{},
	}
}

func (f *fake) call(name string) error {
	f.calls = append(f.calls, name)
	return f.fail[name]
}

// seed commits n events to stream directly, as an earlier run would have.
func (f *fake) seed(stream StreamID, n int, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i < n; i++ {
		f.next[stream]++
		f.events[stream] = append(f.events[stream], Stored{
			Key: Key{NodeID: f.node, Stream: stream, Seq: f.next[stream]}, Class: ClassAdapterEvidence,
			Event: []byte("e"), CommittedAt: at,
		})
	}
	f.storeExists = true
}

// Committer.

func (f *fake) CommitBatch(_ context.Context, stream StreamID, recs []Record) (Commit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("CommitBatch"); err != nil {
		return Commit{}, err
	}
	if f.quotaFull[stream] {
		return Commit{}, &Error{Code: CodeQuotaReached, Detail: string(stream)}
	}
	if f.chain != nil && len(recs) > 0 && recs[0].Class == ClassAudit {
		head, ok := f.heads[stream]
		if !ok {
			head = ChainLink{Hash: f.chain.Genesis()}
		}
		sealed, next, err := SealAudit(f.chain, head, recs)
		if err != nil {
			return Commit{}, err
		}
		recs = slices.Clone(recs)
		for i := range recs {
			recs[i].Event = sealed[i]
		}
		f.heads[stream] = next
	}
	first := f.next[stream] + 1
	for _, r := range recs {
		f.next[stream]++
		ref := ""
		if r.Capture != nil {
			ref = EvidenceRef(r.Capture.SHA256)
			f.captures[ref] = *r.Capture
		}
		f.events[stream] = append(f.events[stream], Stored{
			Key: Key{NodeID: f.node, Stream: stream, Seq: f.next[stream]}, Class: r.Class, Event: r.Event,
			EvidenceRef: ref, SourceCursor: r.SourceCursor, CommittedAt: f.now,
		})
	}
	return Commit{Node: f.node, Stream: stream, FirstSeq: first, Count: len(recs), Sync: f.sync, At: f.now}, nil
}

// StartupEnv.

func (f *fake) Lock(context.Context) (func(), error) {
	if err := f.call("Lock"); err != nil {
		return nil, err
	}
	return func() { f.calls = append(f.calls, "Unlock") }, nil
}

func (f *fake) StoreExists(context.Context) (bool, error) {
	return f.storeExists, f.call("StoreExists")
}

func (f *fake) ReserveExists(_ context.Context, r Reserve) (bool, error) {
	return f.reserves[r], f.call("ReserveExists:" + string(r))
}

func (f *fake) ReleaseReserve(_ context.Context, r Reserve) error {
	if err := f.call("ReleaseReserve:" + string(r)); err != nil {
		return err
	}
	if f.reserves[r] {
		f.reserves[r] = false
		f.free += f.reserveSize(r)
	}
	return nil
}

func (f *fake) reserveSize(r Reserve) int64 {
	if r == ReserveRecovery {
		return 512 << 10
	}
	return 128 << 10
}

func (f *fake) FreeBytes(context.Context) (int64, error) { return f.free, f.call("FreeBytes") }

func (f *fake) Open(context.Context) (RecoveryStore, error) {
	if err := f.call("Open"); err != nil {
		return nil, err
	}
	if f.reserves[ReserveRecovery] {
		f.violations = append(f.violations, "store opened with the recovery reserve still in place")
	}
	if f.storeExists && !f.reserves[ReserveRecovery] && f.reserves[ReserveLastResort] && !f.calledRelease(ReserveRecovery) {
		f.violations = append(f.violations, "store opened without releasing any reserve")
	}
	f.opened = true
	f.storeExists = true
	return f, nil
}

func (f *fake) calledRelease(r Reserve) bool {
	for _, c := range f.calls {
		if c == "ReleaseReserve:"+string(r) {
			return true
		}
	}
	return false
}

func (f *fake) CreateReserve(_ context.Context, r Reserve, bytes int64) error {
	if err := f.call("CreateReserve:" + string(r)); err != nil {
		return err
	}
	if f.free < bytes {
		return fmt.Errorf("%d free, %d needed", f.free, bytes)
	}
	f.free -= bytes
	f.reserves[r] = true
	return nil
}

// RecoveryStore.

func (f *fake) CheckSettings(context.Context) error { return f.call("CheckSettings") }
func (f *fake) QuickCheck(context.Context) error    { return f.call("QuickCheck") }
func (f *fake) Close() error                        { f.opened = false; return f.call("Close") }

func (f *fake) Usage(context.Context) (int64, int64, error) {
	var n int64
	for _, ev := range f.events {
		n += int64(len(ev))
	}
	return n * f.eventSize, f.limit, f.call("Usage")
}

func (f *fake) CompactStep(context.Context, int) (bool, error) {
	if err := f.call("CompactStep"); err != nil {
		return false, err
	}
	if f.freePages > 0 {
		f.freePages--
	}
	return f.freePages > 0, nil
}

func (f *fake) SaveCursor(_ context.Context, c Cursor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("SaveCursor"); err != nil {
		return err
	}
	cur := f.cursors[c.Stream][c.Consumer]
	if c.Through < cur {
		return &Error{Code: CodeCursorRegress, Detail: fmt.Sprintf("%d < %d", c.Through, cur)}
	}
	if c.Through > f.next[c.Stream] {
		return &Error{Code: CodeCursorAhead, Detail: fmt.Sprintf("%d > %d", c.Through, f.next[c.Stream])}
	}
	if f.cursors[c.Stream] == nil {
		f.cursors[c.Stream] = map[ConsumerID]Seq{}
	}
	f.cursors[c.Stream][c.Consumer] = c.Through
	return nil
}

func (f *fake) LoadCursors(_ context.Context, stream StreamID) ([]Cursor, error) {
	if err := f.call("LoadCursors"); err != nil {
		return nil, err
	}
	var out []Cursor
	for id, s := range f.cursors[stream] {
		out = append(out, Cursor{Consumer: id, Stream: stream, Through: s})
	}
	return out, nil
}

func (f *fake) LastCommitted(_ context.Context, stream StreamID) (Seq, error) {
	return f.next[stream], f.call("LastCommitted")
}

func (f *fake) LastCommittedBy(_ context.Context, stream StreamID, t time.Time) (Seq, error) {
	var s Seq
	for _, e := range f.events[stream] {
		if !e.CommittedAt.After(t) {
			s = e.Key.Seq
		}
	}
	return s, f.call("LastCommittedBy")
}

func (f *fake) FirstRetained(_ context.Context, stream StreamID) (Seq, error) {
	if ev := f.events[stream]; len(ev) > 0 {
		return ev[0].Key.Seq, nil
	}
	return 0, nil
}

func (f *fake) PruneStep(_ context.Context, b Boundary, max int) (int, error) {
	if err := f.call("PruneStep"); err != nil {
		return 0, err
	}
	if f.pruneLimit > 0 && f.pruneSteps >= f.pruneLimit {
		return 0, errInjected
	}
	f.pruneSteps++
	ev := f.events[b.Stream()]
	n := 0
	for n < len(ev) && n < max && ev[n].Key.Seq <= b.Through() {
		n++
	}
	for _, e := range ev[:n] {
		if e.Class == ClassAudit {
			f.anchors[b.Stream()] = ChainLink{Seq: e.Key.Seq, Hash: sha256.Sum256(e.Event)}
		}
	}
	f.events[b.Stream()] = ev[n:]
	f.free += int64(n) * f.eventSize // pages handed back by compaction, modelled here
	return n, nil
}

func (f *fake) Read(_ context.Context, stream StreamID, after Seq, max int) ([]Stored, error) {
	var out []Stored
	for _, e := range f.events[stream] {
		if e.Key.Seq > after && len(out) < max {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fake) ReadCapture(_ context.Context, ref string) (Capture, error) {
	c, ok := f.captures[ref]
	if !ok {
		return Capture{}, &Error{Code: CodeInvalid, Detail: "no capture " + ref}
	}
	return c, nil
}

func (f *fake) ChainAnchor(_ context.Context, stream StreamID) (ChainLink, error) {
	if f.chain == nil {
		return ChainLink{}, &Error{Code: CodeInvalid, Detail: "no audit stream"}
	}
	if a, ok := f.anchors[stream]; ok {
		return a, nil
	}
	return ChainLink{Hash: f.chain.Genesis()}, nil
}

// retained lists the seqs still stored for stream.
func (f *fake) retained(stream StreamID) []Seq {
	var out []Seq
	for _, e := range f.events[stream] {
		out = append(out, e.Key.Seq)
	}
	return out
}
