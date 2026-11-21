package sensorlink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// This file is the node's intake on C13 0.2 and 0.3 (CH-10 to CH-18,
// CH-32, CH-33, CH-36, CH-40): it reads one connection that the node hands
// it after the TLS handshake and the node's node-hello, judges the sensor's
// hello, places each record in its run, keeps the position in the
// observation stream's source cursor, and sends acks. The pure checks are
// contracts/netobs's; this file acts on their verdicts.
//
// Not wired (F-027's gate, D4-96): nothing outside the tests calls
// ServeConn. The dialer, node-hello and the coverage gaps other than lost
// are not here (P4-4-INT's split, docs/phase4/D5-p44int-split.md); the
// heartbeat baselines, the run file and the health-event pool are
// health.go's and runfile.go's, the skew estimate and its marks skew.go's,
// the break rule backlog.go's and the late index lateindex.go's.

// The node's channel bounds (CH-4, CH-18, CH-40; C13 0.2 §12). They are the
// node's constants, not C13's.
const (
	HelloTimeout = 10 * time.Second
	IdleTimeout  = 30 * time.Second
	// MaxSkew is max_skew_ms: a lost span's cut end is at most the node's
	// receipt time plus it (CH-40).
	MaxSkew = 2000 * time.Millisecond
	// MaxLinkCursorBytes bounds the cursor (CH-18; D1's ruling 6846045180
	// on #645).
	MaxLinkCursorBytes = 4096
	// cursorSpacing: a save of the cursor on its own, after a refusal, a
	// drop, a duplicate, a hold or a gap, is made at most once a second
	// (CH-17).
	cursorSpacing = time.Second
)

// The alarms the intake raises (CH-13, CH-15, CH-40; #644 §1.4).
const (
	AlarmGapUndeclared    = "sensor-gap-undeclared"
	AlarmCoverageMismatch = "sensor-coverage-mismatch"
	AlarmBufferSmall      = "sensor-buffer-small"
	AlarmRecordsLost      = "sensor-records-lost"
	AlarmPositionNotSaved = "sensor-position-not-saved"
)

// The intake's other names.
const (
	// RefusedDuplicate counts, under Stats.Dropped, a record above L and at
	// or below P (CH-14).
	RefusedDuplicate = "duplicate"
	// ClosedBeforeHello is a link_closes key, not a close reason (CH-11).
	ClosedBeforeHello = "closed-before-hello"
	// RefusedOtherMinor is a record of another minor than the hello's
	// (CH-36).
	RefusedOtherMinor = string(netobs.CodeSchema)
	// sensor-gap-undeclared's reasons (CH-13, CH-15).
	gapReasonRuns, gapReasonSeq = "runs", "seq"
)

// Conn is one sensor connection, after the handshake: net.Conn's subset.
type Conn interface {
	io.Reader
	io.Writer
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

// Enrolment is what the node holds for the key that authenticated the
// connection (CH-12, CH-13, CH-32; sensors.json and network_sensor).
type Enrolment struct {
	SensorID   string
	Generation uint64
	// Began is the generation at which the node's position began: a cursor
	// saved under a lower generation reads as none (CH-12).
	Began uint64
	// ConfigDigest is the expected digest, network_sensor's (CH-32).
	ConfigDigest string
}

// CursorStore is the observation stream's source cursor (CH-18): read at
// the connection's start, and saved on its own when no record carries it.
type CursorStore interface {
	SourceCursor(ctx context.Context) ([]byte, error)
	SaveSourceCursor(ctx context.Context, b []byte) error
}

// PinStore keeps the first pinned_by accepted in each generation
// (sensors.json, CH-33).
type PinStore interface {
	PinnedBy(generation uint64) (string, error)
	KeepPinnedBy(generation uint64, v string) error
}

// Owed is what the node owes the health stream: a new run's prior
// (sensor.run-loss, CH-16) and each admitted span's lost gap
// (sensor.coverage-gap, CH-40). Each stays marked in the cursor until its
// event has committed. A write repeated after a failed save is the same
// event under this key: for the run loss, the sensor and run_id (with
// run_counter); for a lost gap, the sensor, run_id, from_utc, to_utc and
// the cut end. Generation is carried but is not part of either key: a run
// resumed under a new generation (row 5b) writes its owed events again
// under the new one. A span widened or merged keeps its from_utc but is a
// new event (D4's N4 on #732). One call holds a run's events together, so
// a writer must be idempotent per event, not per call.
type Owed struct {
	Generation, RunCounter uint64
	RunID                  string
	Prior                  *HeldPrior
	Spans                  []HeldSpan
}

// HeldSpan is a lost span as stated, with its cut end, fixed once, and its
// marks (CH-40).
type HeldSpan struct {
	FromUTC string `json:"from_utc"`
	ToUTC   string `json:"to_utc"`
	CutUTC  string `json:"cut_utc"`
	// Owed: its lost gap's event has not committed. Marked: node.lost has
	// carried its window on a stored observation.
	Owed   bool `json:"owed,omitempty"`
	Marked bool `json:"marked,omitempty"`
}

// HeldPrior is a new run's prior as the cursor keeps it (CH-16).
type HeldPrior struct {
	RunsSkipped uint64     `json:"runs_skipped"`
	RecordsLost uint64     `json:"records_lost"`
	PreviousEnd string     `json:"previous_end"`
	StartedBy   string     `json:"started_by"`
	Spans       []HeldSpan `json:"spans"`
	Owed        bool       `json:"owed,omitempty"`
}

// Cursor is the part of CH-18's cursor this intake keeps: the position,
// G and D, the run's totals, write_no, Ds, the last newest_seq, the run's
// digest, the heartbeat baselines, and its spans and prior. It holds one run: what an earlier run owed is
// written before row 6's save replaces it (D1's ruling on #732). Its
// stored form is section 1.4's text form (cursorform.go); the JSON tags
// serve clone only.
type Cursor struct {
	Generation uint64 `json:"generation"`
	RunCounter uint64 `json:"run_counter"`
	RunID      string `json:"run_id"`
	Taken      uint64 `json:"taken"`
	G          uint64 `json:"g"`
	D          uint64 `json:"d"`
	Refused    uint64 `json:"refused"`
	Dropped    uint64 `json:"dropped"`
	Ds         uint64 `json:"ds"`
	NewestSeq  uint64 `json:"newest_seq"`
	Digest     string `json:"digest"`
	// WriteNo is the run file's write number as last saved here (section
	// 1.1): 0 when no file has been written.
	WriteNo uint64 `json:"write_no"`
	// The run's heartbeat baselines (section 1.8): each counter as last
	// taken, nil when none is held, and the egress mark, "" when none.
	FramesOutgoing *uint64    `json:"frames_outgoing,omitempty"`
	DropsHolder    *uint64    `json:"drops_holder,omitempty"`
	FramesOverlong *uint64    `json:"frames_overlong,omitempty"`
	DropsDriver    *uint64    `json:"drops_driver,omitempty"`
	Egress         string     `json:"egress,omitempty"`
	Spans          []HeldSpan `json:"spans,omitempty"`
	Prior          *HeldPrior `json:"prior,omitempty"`
	// M is the sensor's clock as last read (section 1.5), zero before the
	// sensor's first K: written by Link.encode at each write.
	M time.Time `json:"m,omitzero"`
	// W, the moment accounted through, with its heartbeat's seq and
	// at_utc; R; and, from W's heartbeat, each interface's packets and the
	// at_utc of its last rise in the run, in the bytewise order of the
	// interfaces' names (section 1.4; watch.go). Each zero or empty when
	// none is held; written by Link.encode at each write, as M is.
	W      time.Time   `json:"w,omitzero"`
	WSeq   uint64      `json:"w_seq,omitempty"`
	WAtUTC time.Time   `json:"w_at,omitzero"`
	R      time.Time   `json:"r,omitzero"`
	Ifaces []IfaceMark `json:"ifaces,omitempty"`
	// Causes are the causes of the gap open now, held in W, as bits of
	// gapCauses; Held is the gap held for the floor (CH-18; gap.go). Both
	// written by Link.encode at each write, as W is.
	Causes uint16   `json:"causes,omitempty"`
	Held   *HeldGap `json:"held,omitempty"`
}

func checkCursorBytes(b []byte) error {
	if len(b) > MaxLinkCursorBytes {
		return fmt.Errorf("sensorlink: a cursor of %d bytes, above MaxLinkCursorBytes %d", len(b), MaxLinkCursorBytes)
	}
	return nil
}

func (c *Cursor) clone() *Cursor {
	if c == nil {
		return nil
	}
	b, _ := json.Marshal(c)
	var out Cursor
	_ = json.Unmarshal(b, &out)
	return &out
}

// stated is the run's spans as stated, for netobs's widening check.
func (c *Cursor) stated() []netobs.Span {
	out := make([]netobs.Span, len(c.Spans))
	for i, s := range c.Spans {
		out[i] = netobs.Span{FromUTC: s.FromUTC, ToUTC: s.ToUTC}
	}
	return out
}

// ConnStats are the intake's counts since the link was made.
type ConnStats struct {
	// Closes counts the node's closes by reason (CH-11), and
	// closed-before-hello.
	Closes map[string]uint64
	// TickEarly counts ticks under TickMinSpacing (CH-8); SpansCut the
	// spans cut once (CH-40); LostGaps the lost gaps opened.
	TickEarly, SpansCut, LostGaps uint64
	// ForkHeld: a hello closed run-forked (CH-13 row 4).
	ForkHeld bool
	// Frames counts the frames read and acted on, the hello's included.
	Frames uint64
	// Connected is 1 while a connection is served.
	Connected int
}

// conn is one connection's state.
type conn struct {
	c     Conn
	en    Enrolment
	hello *netobs.SensorHello
	cur   *Cursor
	saved uint64 // the T saved in the store
	// pending: the cursor holds a change not saved; lastSave is when the
	// last save on its own was made, on the monotonic clock.
	pending  bool
	lastSave time.Duration
	l        uint64 // L (CH-14)
	sent     uint64 // the latest tick's sent_seq
	acked    uint64
	ackSent  bool
	lastTick *netobs.Tick
	tickAt   time.Duration
	// fromStart: the run was accepted as new on this connection, and every
	// seq of it has been read with no loss declared (CH-27).
	fromStart bool
	// owedTry is when the owed events were last tried, on the monotonic
	// clock; owedFailed, that the try failed, raised once a connection.
	owedTry    time.Duration
	owedFailed bool
	// held: the read loop's step before the frame being acted on lasted
	// longer than AckMaxDelay (section 1.5 item 6).
	held bool
	// tickFrame: the frame being acted on is a tick.
	tickFrame bool
}

// connGuard is the link's one live connection (CH-3) and the close a
// decision asks for (CH-37, CH-11's state-unread).
type connGuard struct {
	mu      sync.Mutex
	live    Conn
	request string
}

// ServeConn serves one connection of the 0.2 or 0.3 channel until it
// closes, and returns the node's close reason, or "" when the sensor ended
// the stream. It closes c. The caller has authenticated the peer and sent
// node-hello; en is the enrolment of the key that authenticated.
func (l *Link) ServeConn(ctx context.Context, c Conn, en Enrolment) string {
	defer c.Close()
	g := &l.guard
	g.mu.Lock()
	if g.live != nil {
		g.mu.Unlock()
		l.countClose(netobs.CloseSecondConnection)
		return netobs.CloseSecondConnection
	}
	g.live, g.request = c, ""
	l.mu.Lock()
	l.conn.Connected = 1
	l.mu.Unlock()
	g.mu.Unlock()
	// A cancel is a decision like any other: it acts before any further
	// frame or ack, and closes as shutdown (D3's B2 on #732).
	stop := context.AfterFunc(ctx, func() { l.CloseConn(netobs.CloseShutdown) })
	defer func() {
		stop()
		l.closeCursor()
		g.mu.Lock()
		g.live = nil
		g.mu.Unlock()
		l.mu.Lock()
		l.conn.Connected = 0
		l.mu.Unlock()
	}()
	reason := l.serveConn(ctx, &conn{c: c, en: en})
	if reason != "" {
		l.countClose(reason)
	}
	return reason
}

// CloseConn closes the live connection for a decision: enrolment (CH-37),
// shutdown, or state-unread (CH-11). From the request on, the read loop
// acts on no further frame and sends no ack (CH-37 steps 1 and 2): a read
// in progress, or an ack being written, ends at once.
func (l *Link) CloseConn(reason string) {
	g := &l.guard
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.live == nil {
		return
	}
	if g.request == "" {
		g.request = reason // the first decision wins (D3's N3 on #732)
	}
	_ = g.live.SetReadDeadline(time.Now())
	_ = g.live.SetWriteDeadline(time.Now())
}

func (l *Link) requested() string {
	l.guard.mu.Lock()
	defer l.guard.mu.Unlock()
	return l.guard.request
}

// decided is the close a decision asks for: CloseConn's request, or
// shutdown once ctx is done. The context is read here as well as through
// its AfterFunc, which runs on its own goroutine and may not have run yet
// when the cancel has returned.
func (l *Link) decided(ctx context.Context) string {
	if r := l.requested(); r != "" {
		return r
	}
	if ctx.Err() != nil {
		return netobs.CloseShutdown
	}
	return ""
}

func (l *Link) countClose(reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.conn.Closes[reason]++
}

// ConnStats returns a copy of the intake's counts.
func (l *Link) ConnStats() ConnStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.conn
	s.Closes = clone(s.Closes)
	return s
}

func (l *Link) raise(alarm, detail string) {
	if l.opt.Raise != nil {
		l.opt.Raise(alarm, detail)
	}
	if l.opt.Health != nil && slices.Contains(poolAlarms, alarm) {
		l.opt.Health.alarm(alarm, detail)
	}
}

// read reads one frame with the deadline d. It returns the close reason
// for a frame above the cap, a deadline, the context or a decision, and
// eof when the sensor ended the stream.
func (l *Link) read(ctx context.Context, cn *conn, d time.Duration, timeout string) (b []byte, reason string, eof bool) {
	// The request is checked, and the deadline set, under the lock
	// CloseConn takes, so a decision either ends this read or is seen
	// here: its deadline is never overwritten (D3's B2 on #732).
	g := &l.guard
	g.mu.Lock()
	r := g.request
	if r == "" && ctx.Err() != nil {
		r = netobs.CloseShutdown
	}
	if r == "" {
		_ = cn.c.SetReadDeadline(time.Now().Add(d))
	}
	g.mu.Unlock()
	if r != "" {
		return nil, r, false
	}
	b, err := netobs.ReadFrame(cn.c)
	if r := l.requested(); r != "" {
		return nil, r, false
	}
	switch {
	case err == nil:
		return b, "", false
	case errors.Is(err, netobs.ErrFrameTooLarge):
		l.mu.Lock()
		l.stats.FramesTooLarge++
		l.mu.Unlock()
		return nil, netobs.CloseFrameTooLarge, false
	case ctx.Err() != nil:
		return nil, netobs.CloseShutdown, false
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil, timeout, false
	default:
		return nil, "", true
	}
}

// serveConn holds curMu while it acts on a frame, never while it reads
// or writes the connection, so WriteOwed waits for one frame at most.
func (l *Link) serveConn(ctx context.Context, cn *conn) string {
	b, reason, eof := l.read(ctx, cn, l.timeouts().Hello, netobs.CloseHelloTimeout)
	switch {
	case eof:
		l.countClose(ClosedBeforeHello)
		return ""
	case reason != "":
		return reason
	}
	reason = l.locked(func() string {
		if r := l.decided(ctx); r != "" {
			return r // a decision made while the frame was read
		}
		cur, err := l.openCursor(ctx) // from the read on, a release records its change for this connection
		if err != nil {
			return netobs.CloseStateUnread // the position cannot be read (CH-18)
		}
		return l.acceptHello(ctx, cn, cur, b)
	})
	if reason != "" {
		return reason
	}
	if r := l.writeAck(ctx, cn); r != "" {
		return r
	}
	for {
		b, reason, eof := l.read(ctx, cn, l.timeouts().Idle, netobs.CloseIdle)
		if eof {
			l.locked(func() string {
				l.checkGap(cn.cur) // when a connection of the run ends (CH-15)
				l.flush(ctx, cn, true)
				return ""
			})
			return ""
		}
		if reason == "" {
			step := l.opt.Monotonic()
			reason = l.locked(func() string {
				if r := l.decided(ctx); r != "" {
					return r // a decision made while the frame was read
				}
				l.foldLive(cn)
				if r := l.frame(ctx, cn, b); r != "" {
					return r
				}
				// The frame was accepted: the next break begins after it, and a
				// backlog is through once the run's position reaches its end
				// (CH-39).
				l.frameAccepted()
				l.positionRead(cn.hello.RunID, cn.cur.Taken, !cn.tickFrame)
				l.flush(ctx, cn, false)
				l.retryOwed(ctx, cn)
				return ""
			})
			// The next frame waits in the connection while this one is acted
			// on: a step past AckMaxDelay delays its receipt (F4).
			cn.held = l.opt.Monotonic()-step > AckMaxDelay
			if reason == "" {
				reason = l.writeAck(ctx, cn)
			}
		} else {
			l.mu.Lock()
			l.conn.Frames++ // a close the frame did not decide is still a frame acted on
			l.mu.Unlock()
		}
		if reason != "" {
			if reason != netobs.CloseStore {
				l.locked(func() string { l.flush(ctx, cn, true); return "" })
			}
			return reason
		}
	}
}

// locked runs f under curMu and counts the frame it acted on.
func (l *Link) locked(f func() string) string {
	l.curMu.Lock()
	defer l.curMu.Unlock()
	r := f()
	l.mu.Lock()
	l.conn.Frames++
	l.mu.Unlock()
	return r
}

func (l *Link) timeouts() ConnTimeouts {
	t := l.opt.Timeouts
	if t.Hello <= 0 {
		t.Hello = HelloTimeout
	}
	if t.Idle <= 0 {
		t.Idle = IdleTimeout
	}
	return t
}

// ConnTimeouts are CH-4's two waits; zero is the default.
type ConnTimeouts struct{ Hello, Idle time.Duration }

// loadCursor reads the cursor, nil when there is none.
func (l *Link) loadCursor(ctx context.Context) (*Cursor, error) {
	if l.opt.Cursor == nil {
		return nil, errors.New("sensorlink: no cursor store")
	}
	b, err := l.opt.Cursor.SourceCursor(ctx)
	if err != nil || b == nil {
		if err == nil {
			l.takeM(time.Time{}) // no cursor: no M, and the start's first break begins
		}
		return nil, err
	}
	c, err := decodeCursor(b)
	if err == nil {
		// M is the sensor's, whatever the position's generation, so it is
		// taken before acceptHello reads a lower generation as none
		// (section 1.4; D6's N3 on #641). W and R are node times, taken
		// the same way.
		l.takeM(c.M)
		l.takeWatch(c)
	}
	return c, err
}

// encode is c's stored form with M, W, R and the interfaces kept with W
// as the link holds them now (section 1.4).
func (l *Link) encode(c *Cursor) ([]byte, error) {
	c.M = l.mNow()
	l.watchInto(c)
	return encodeCursor(c)
}

// saveCursor saves c on its own, with what releases moved since the 0.2
// path's cursor last took it and what their own saves did not write, under
// cmu so that no release writes between the two. Only a save that
// succeeds puts the releases' changes in c.
func (l *Link) saveCursor(ctx context.Context, c *Cursor) error {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	c.WriteNo = max(c.WriteNo, l.writeNo)
	next := c
	if l.moved != nil || l.unsaved != nil {
		next = c.clone()
		l.moved.apply(next)
		l.unsaved.apply(next)
	}
	b, err := l.encode(next)
	if err != nil {
		return err
	}
	if err := l.opt.Cursor.SaveSourceCursor(ctx, b); err != nil {
		return err
	}
	l.moved.apply(c)
	l.unsaved.apply(c)
	l.moved, l.unsaved = nil, nil
	l.pos, l.posRead = c.clone(), true
	return nil
}

// posMove is what releases changed in the position while the 0.2 path
// held its cursor in memory (section 1.4 items 2 and 3; D4's N3 on #732).
type posMove struct {
	run              string // the position's run when the release ran
	taken            uint64 // the highest seq of run the releases disposed of
	refused, dropped uint64 // what the releases refused and dropped
	unmark           []netobs.Span
}

// apply puts m in c: T moves only within m's run, the totals go to c's run
// (a newer one's included), and a window that a dropped record carried is
// unmarked, so the run's next stored observation carries it. A nil m
// changes nothing.
func (m *posMove) apply(c *Cursor) {
	if m == nil {
		return
	}
	if c.RunID == m.run {
		c.Taken = max(c.Taken, m.taken)
		for _, w := range m.unmark {
			unmark(c, w)
		}
	}
	c.Refused += m.refused
	c.Dropped += m.dropped
}

func (m *posMove) empty() bool {
	return m == nil || (m.taken == 0 && m.refused == 0 && m.dropped == 0 && len(m.unmark) == 0)
}

// merge is m followed by n, in n's run: m's T and unmarks carry only when
// m is of n's run, its totals always.
func (m *posMove) merge(n *posMove) *posMove {
	out := *n
	out.unmark = slices.Clone(n.unmark)
	if m == nil {
		return &out
	}
	out.refused += m.refused
	out.dropped += m.dropped
	if m.run == n.run {
		out.taken = max(out.taken, m.taken)
		out.unmark = append(slices.Clone(m.unmark), out.unmark...)
	}
	return &out
}

// unmark clears the mark of the held span whose node.lost window is w.
func unmark(c *Cursor, w netobs.Span) {
	f := func(list []HeldSpan) {
		for i := range list {
			s := &list[i]
			if s.Marked && parseUTC(s.FromUTC).Equal(parseUTC(w.FromUTC)) && parseUTC(s.CutUTC).Equal(parseUTC(w.ToUTC)) {
				s.Marked = false
			}
		}
	}
	if c.Prior != nil {
		f(c.Prior.Spans)
	}
	f(c.Spans)
}

// foldLive puts what releases moved in the connection's cursor before a
// frame is acted on, so the duplicate check reads the position saved now
// (section 1.4 item 4). l.moved holds only what the releases wrote, so
// those writes are durable already; what they did not write is in
// l.unsaved, which raises no cn.saved (D3's B1 on #742).
func (l *Link) foldLive(cn *conn) {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	if l.moved == nil || cn.cur == nil {
		return
	}
	l.moved.apply(cn.cur)
	if cn.cur.RunID == l.moved.run {
		cn.saved = max(cn.saved, l.moved.taken)
	}
	l.moved, cn.pending = nil, true
}

// openCursor begins the time the 0.2 path holds a cursor in memory, and
// reads that cursor in the same hold of cmu: a release is either in what
// it reads or recorded in l.moved for it, never both (D6's B3 on #742).
func (l *Link) openCursor(ctx context.Context) (*Cursor, error) {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	l.curOpen, l.moved = true, nil
	c, err := l.loadCursor(ctx)
	if err == nil {
		l.pos, l.posRead = c, true
		l.tookWriteNo(c)
	}
	return c.clone(), err
}

// tookWriteNo takes the write number a cursor read holds, so every later
// write of the position carries it, row 6's new cursor included (D6's B3
// on #747). The caller holds cmu.
func (l *Link) tookWriteNo(c *Cursor) {
	if c != nil {
		l.writeNo = max(l.writeNo, c.WriteNo)
	}
}

// closeCursor ends it: every release since writes its own change.
func (l *Link) closeCursor() {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	l.curOpen, l.moved = false, nil
}

// saveWriteNo saves the run file's write number n in the position, as
// last written, once the file is renamed (section 1.1). Every later write
// of the position carries it. A sensor with no cursor has nothing to
// carry it: its database reads as lost at the next start.
func (l *Link) saveWriteNo(ctx context.Context, n uint64) error {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	l.writeNo = max(l.writeNo, n)
	if l.opt.Cursor == nil {
		return nil
	}
	if err := l.readPos(ctx); err != nil {
		return err
	}
	if l.pos == nil || l.pos.WriteNo >= n {
		return nil
	}
	c := l.pos.clone()
	c.WriteNo = l.writeNo
	b, err := l.encode(c)
	if err != nil {
		return err
	}
	if err := l.opt.Cursor.SaveSourceCursor(ctx, b); err != nil {
		return err
	}
	l.pos = c
	return nil
}

// readCursor reads the position for RunFile.Start, nil when none.
func (l *Link) readCursor(ctx context.Context) (*Cursor, error) {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	if l.opt.Cursor == nil {
		return nil, errors.New("sensorlink: no cursor store")
	}
	if err := l.readPos(ctx); err != nil {
		return nil, err
	}
	return l.pos.clone(), nil
}

// saveStart saves the position the start changed (RunFile.Start).
func (l *Link) saveStart(ctx context.Context, c *Cursor) error {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	c.WriteNo = max(c.WriteNo, l.writeNo)
	b, err := l.encode(c)
	if err != nil {
		return err
	}
	if err := l.opt.Cursor.SaveSourceCursor(ctx, b); err != nil {
		return err
	}
	l.pos = c.clone()
	return nil
}

// flush saves a pending cursor on its own, at most once a second unless
// now is set.
func (l *Link) flush(ctx context.Context, cn *conn, now bool) bool {
	if !cn.pending || cn.cur == nil {
		return true
	}
	at := l.opt.Monotonic()
	if !now && cn.lastSave != 0 && at-cn.lastSave < cursorSpacing {
		return true
	}
	if err := l.saveCursor(ctx, cn.cur); err != nil {
		return false
	}
	cn.pending, cn.lastSave, cn.saved = false, at, cn.cur.Taken
	return true
}

// writeAck sends an ack when the saved T, bounded by what was read and
// sent on the connection, has risen (CH-17, CH-9).
func (l *Link) writeAck(ctx context.Context, cn *conn) string {
	if r := l.decided(ctx); r != "" {
		return r // no ack after a decision (CH-37)
	}
	seq := min(cn.saved, max(cn.l, cn.sent))
	if cn.ackSent && seq <= cn.acked {
		return ""
	}
	h := cn.hello
	b, _ := json.Marshal(netobs.Ack{Schema: netobs.Identifier02, Type: netobs.TypeAck, RunCounter: h.RunCounter, RunID: h.RunID,
		Seq: strconv.FormatUint(seq, 10)})
	// The decision is checked again, and the deadline set, under the lock
	// CloseConn takes, as read does: a decision made since the check above
	// is seen here, and its deadline is never overwritten (D3's N2 on #732).
	g := &l.guard
	g.mu.Lock()
	r := g.request
	if r == "" && ctx.Err() != nil {
		r = netobs.CloseShutdown
	}
	if r == "" {
		_ = cn.c.SetWriteDeadline(time.Now().Add(l.timeouts().Idle))
	}
	g.mu.Unlock()
	if r != "" {
		return r
	}
	if err := netobs.WriteFrame(cn.c, b); err != nil {
		if r := l.decided(ctx); r != "" {
			return r // the decision cut the write
		}
		return netobs.CloseIdle
	}
	cn.acked, cn.ackSent = seq, true
	return ""
}

// acceptHello judges the connection's first frame (CH-13) and, when it is
// accepted, saves what it changes before acting on it.
func (l *Link) acceptHello(ctx context.Context, cn *conn, cur *Cursor, b []byte) string {
	fs, err := netobs.DecodeFromSensor(b)
	if err != nil || fs.Hello == nil {
		return netobs.CloseHello // row 1; a 0.1 peer, another type first
	}
	h := fs.Hello
	pinned, err := l.opt.Pins.PinnedBy(cn.en.Generation)
	if err != nil {
		return netobs.CloseStateUnread
	}
	st := netobs.HelloState{SensorID: cn.en.SensorID, Generation: cn.en.Generation, Began: cn.en.Began,
		PinnedBy: pinned, ConfigDigest: cn.en.ConfigDigest}
	live := cur != nil && cur.Generation >= cn.en.Began
	if live {
		st.Position = &netobs.Position{Generation: cur.Generation, RunCounter: cur.RunCounter, RunID: cur.RunID, Taken: cur.Taken, D: cur.D}
		st.Spans, st.Ds = cur.stated(), cur.Ds
	}
	v := netobs.JudgeHello(st, h)
	if v.Close != "" {
		if v.Close == netobs.CloseRunForked {
			l.mu.Lock()
			l.conn.ForkHeld = true
			l.mu.Unlock()
		}
		return v.Close
	}
	recv := l.now()
	first, newest, drops := num(h.FirstSeq), num(h.NewestSeq), num(h.DropsChannel)
	var next *Cursor
	var cuts, opened uint64
	if v.Accept == netobs.HelloNewRun {
		// CH-15's check for the run the cursor holds runs first, before the
		// save below overwrites G and D (D5's N9 on #634).
		if cur != nil {
			l.checkGap(cur)
			// The replaced run's last capture loss and the totals it counts
			// up to are in the run file before the save forgets them
			// (section 1.4; D1's rulings 6850475569 and 6850665387 on #655).
			if hl := l.opt.Health; hl != nil {
				if err := hl.beforeReplace(ctx, cur); err != nil {
					l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: run %s's capture totals were not written to sensorrun.json: %v", h.SensorID, cur.RunID, err))
					return netobs.ClosePositionNotSaved
				}
			}
			// What the replaced cursor owes, a position that reads as none
			// included, is written under its own identity before the save
			// replaces it; on a failure nothing is saved or kept (CH-12,
			// CH-16, CH-40; option (a), D1's ruling on #732).
			if r := l.writeReplaced(ctx, h.SensorID, cur); r != "" {
				return r
			}
		}
		next = &Cursor{Generation: cn.en.Generation, RunCounter: num(h.RunCounter), RunID: h.RunID,
			Taken: first - 1, G: first - 1, D: drops, Digest: h.ConfigDigest, NewestSeq: newest}
		p := h.Prior
		next.Prior = &HeldPrior{RunsSkipped: num(p.RunsSkipped), RecordsLost: num(p.RecordsLost), PreviousEnd: p.PreviousEnd,
			StartedBy: p.StartedBy, Spans: admit(nil, p.Lost, h.SensorUTC, recv, &cuts, &opened), Owed: true}
		next.Spans = admit(nil, h.Lost, h.SensorUTC, recv, &cuts, &opened)
		if v.SpansWidened {
			next.Ds = drops
		}
	} else {
		next = cur.clone()
		next.Generation = cn.en.Generation // row 5b's save
		next.D, next.NewestSeq = max(next.D, drops), newest
		if next.Digest == "" {
			next.Digest = h.ConfigDigest
		}
		if first > next.Taken+1 {
			next.G += first - next.Taken - 1
		}
		next.Taken = max(next.Taken, first-1)
		if v.SpansWidened {
			next.Spans, next.Ds = admit(next.Spans, h.Lost, h.SensorUTC, recv, &cuts, &opened), drops
		}
	}
	// The hello's sample and its stated spans move the floor before the
	// save, which carries M (section 1.5); the step check runs before the
	// sample takes the receipt's time.
	if err := l.stepAtReceipt(ctx); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: W and R moved by a step of the node's clock were not saved: %v", h.SensorID, err))
		return netobs.ClosePositionNotSaved
	}
	_, onset := l.sample(h.SensorUTC, true, false)
	if h.Prior != nil {
		l.spansRaise(h.Prior.Lost)
	}
	l.spansRaise(h.Lost)
	if onset {
		l.skewOnset(ctx)
	}
	if err := l.saveCursor(ctx, next); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: the position for run %s was not saved: %v", h.SensorID, h.RunID, err))
		return netobs.ClosePositionNotSaved
	}
	if pinned == "" {
		if err := l.opt.Pins.KeepPinnedBy(cn.en.Generation, h.PinnedBy); err != nil {
			l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: pinned_by was not kept: %v", h.SensorID, err))
			return netobs.ClosePositionNotSaved
		}
	}
	// Accepted.
	l.mu.Lock()
	l.conn.SpansCut += cuts
	l.mu.Unlock()
	cn.hello, cn.cur, cn.saved, cn.l = h, next, next.Taken, first-1
	cn.lastSave = l.opt.Monotonic()
	// Seen from its start (CH-27): accepted as new from seq 1 with no loss
	// declared, or resumed in this process with no gap and none declared
	// since (D4's N1 on #747).
	clean := drops == 0 && len(h.Lost) == 0
	cn.fromStart = clean && (v.Accept == netobs.HelloNewRun && first == 1 ||
		v.Accept != netobs.HelloNewRun && l.startRun == h.RunID && first <= cur.Taken+1)
	l.startRun = ""
	if cn.fromStart {
		l.startRun = h.RunID
	}
	if v.Accept == netobs.HelloNewRun {
		l.runBegan(h.RunID)
	}
	l.resetRun(ctx, h.RunID, v.Accept == netobs.HelloNewRun)
	l.breakEnd(h, cn.en.Generation, next.Taken) // the break ends, before the hello is the last frame
	l.frameAccepted()
	if opened > 0 {
		l.lostOpened(h.SensorID, h.RunID, opened)
	}
	if v.RunsUndeclared {
		l.raise(AlarmGapUndeclared, fmt.Sprintf("sensor %s: reason %s: run %s skipped %s runs, the node counts otherwise", h.SensorID, gapReasonRuns, h.RunID, h.Prior.RunsSkipped))
	}
	if v.DigestMismatch {
		l.raise(AlarmCoverageMismatch, fmt.Sprintf("sensor %s: config_digest %s is not the expected %s", h.SensorID, h.ConfigDigest, cn.en.ConfigDigest))
	}
	if v.BufferSmall {
		l.raise(AlarmBufferSmall, fmt.Sprintf("sensor %s: buffer_bytes %s is below the site floor", h.SensorID, h.BufferBytes))
	}
	l.checkGap(next)
	l.owedInRun(ctx, cn)
	return ""
}

// writeReplaced writes what cur owes before row 6's save replaces it. Owed
// events with no Options.Owed to write them, or a failed write, close
// position-not-saved: the old cursor stays as it was, so the next hello
// writes them again (twice, never not at all).
func (l *Link) writeReplaced(ctx context.Context, sensor string, cur *Cursor) string {
	o, n := owedOf(cur)
	if n == 0 {
		return ""
	}
	err := errors.New("no writer for the health stream")
	if l.opt.Owed != nil {
		err = l.opt.Owed(ctx, o)
	}
	if err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: %d owed events of run %s were not written: %v", sensor, n, cur.RunID, err))
		return netobs.ClosePositionNotSaved
	}
	return ""
}

// owedInRun writes what the run owes; a failure is raised, once a
// connection, and the connection stays open, the marks kept for the next
// attempt (D3's condition 4 on #732), which retryOwed makes. An event
// that waits for its budget is not a failure.
func (l *Link) owedInRun(ctx context.Context, cn *conn) {
	if l.opt.Owed == nil {
		return
	}
	cn.owedTry = l.opt.Monotonic()
	_, n := owedOf(cn.cur)
	switch err := l.writeOwed(ctx, cn); {
	case err == nil:
		cn.owedFailed = false
	case errors.Is(err, ErrHealthHeld):
	case !cn.owedFailed:
		cn.owedFailed = true
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: %d owed events of run %s were not written: %v", l.cfg.SensorID, n, cn.cur.RunID, err))
	}
}

// retryOwed tries the run's owed events again during a live connection,
// at most once a second (D4-116 item 3.5's first limit, closed here).
func (l *Link) retryOwed(ctx context.Context, cn *conn) {
	if l.opt.Owed == nil || cn.cur == nil {
		return
	}
	if _, n := owedOf(cn.cur); n == 0 || l.opt.Monotonic()-cn.owedTry < cursorSpacing {
		return
	}
	l.owedInRun(ctx, cn)
}

// resetRun starts the link's run state for the hello's run: a new run
// clears the open-flow table (CH-13) and the heartbeat baseline.
func (l *Link) resetRun(ctx context.Context, run string, newRun bool) {
	l.mu.Lock()
	if l.stats.RunID != run {
		if l.stats.RunID != "" {
			l.stats.RunChanges++
		}
		l.stats.RunID, l.stats.LastSeq, l.stats.LastCommittedSeq, l.stats.Heartbeat = run, 0, 0, nil
	}
	l.mu.Unlock()
	if newRun {
		l.cmu.Lock()
		l.giveWay(ctx, true)
		l.syncHold()
		l.cmu.Unlock()
	}
}

func (l *Link) lostOpened(sensor, run string, n uint64) {
	l.mu.Lock()
	l.conn.LostGaps += n
	l.mu.Unlock()
	l.raise(AlarmRecordsLost, fmt.Sprintf("sensor %s: run %s declares lost records; a lost coverage gap is open", sensor, run))
}

// owedOf is what c owes, under c's identity, and the number of its events.
func owedOf(c *Cursor) (Owed, int) {
	o := Owed{Generation: c.Generation, RunCounter: c.RunCounter, RunID: c.RunID}
	n := 0
	if c.Prior != nil && c.Prior.Owed {
		o.Prior, n = c.Prior, 1
	}
	for _, s := range c.Spans {
		if s.Owed {
			o.Spans = append(o.Spans, s)
		}
	}
	return o, n + len(o.Spans)
}

// checkGap is CH-15's check: G at most D. The alarm rises once for each
// rise of the excess in a run.
func (l *Link) checkGap(c *Cursor) {
	if c == nil || c.G <= c.D {
		return
	}
	if l.gapRun != c.RunID {
		l.gapRun, l.gapRaised = c.RunID, 0
	}
	if c.G-c.D <= l.gapRaised {
		return
	}
	l.gapRaised = c.G - c.D
	l.raise(AlarmGapUndeclared, fmt.Sprintf("sensor %s: reason %s: run %s has %d records never read beyond the %d declared",
		l.cfg.SensorID, gapReasonSeq, c.RunID, c.G, c.D))
}

// admit adds the stated spans to held under CH-40's rules: a span inside a
// held one changes nothing; a new span is kept with its cut end, fixed
// now; a widened span extends its window back, and forward only when it
// was not cut. Each new or widened span is owed its lost gap. cut counts
// the spans cut, and opened the spans new or widened, each a lost gap.
func admit(held []HeldSpan, stated []netobs.Span, sensorUTC string, recv time.Time, cut, opened *uint64) []HeldSpan {
	out := slices.Clone(held)
	for _, s := range stated {
		from, to := parseUTC(s.FromUTC), parseUTC(s.ToUTC)
		i := slices.IndexFunc(out, func(h HeldSpan) bool {
			return !from.After(parseUTC(h.ToUTC)) && !to.Before(parseUTC(h.FromUTC))
		})
		if i < 0 {
			out = append(out, HeldSpan{FromUTC: canonUTC(from), ToUTC: canonUTC(to), CutUTC: cutEnd(to, sensorUTC, recv, cut), Owed: true})
			*opened++
			continue
		}
		h := &out[i]
		hFrom, hTo := parseUTC(h.FromUTC), parseUTC(h.ToUTC)
		if !from.Before(hFrom) && !to.After(hTo) {
			continue // inside: neither new nor wider
		}
		if from.Before(hFrom) {
			h.FromUTC = canonUTC(from)
		}
		if to.After(hTo) {
			if parseUTC(h.CutUTC).Equal(hTo) { // not cut: the window reaches the new part's cut end (times, not strings: D4's B1 on #732)
				h.CutUTC = cutEnd(to, sensorUTC, recv, cut)
			}
			h.ToUTC = canonUTC(to)
		}
		h.Owed, h.Marked = true, false
		*opened++
	}
	slices.SortFunc(out, func(a, b HeldSpan) int { return parseUTC(a.FromUTC).Compare(parseUTC(b.FromUTC)) })
	for len(out) > netobs.MaxLostSpans {
		// Merge the two closest, as the sensor does: never less time.
		k := 1
		for j := 2; j < len(out); j++ {
			if parseUTC(out[j].FromUTC).Sub(parseUTC(out[j-1].CutUTC)) < parseUTC(out[k].FromUTC).Sub(parseUTC(out[k-1].CutUTC)) {
				k = j
			}
		}
		a, b := out[k-1], out[k]
		a.ToUTC, a.CutUTC, a.Owed, a.Marked = laterUTC(a.ToUTC, b.ToUTC), laterUTC(a.CutUTC, b.CutUTC), true, false
		out = slices.Replace(out, k-1, k+1, a)
	}
	return out
}

// cutEnd is the earliest of the span's to_utc, the message's sensor_utc
// and the node's receipt plus MaxSkew, fixed once; counted when below
// to_utc.
func cutEnd(to time.Time, sensorUTC string, recv time.Time, cut *uint64) string {
	end := to
	if s := parseUTC(sensorUTC); s.Before(end) {
		end = s
	}
	if r := recv.Add(MaxSkew); r.Before(end) {
		end = r
	}
	if end.Before(to) {
		*cut++
	}
	return canonUTC(end)
}

// canonUTC is the one form the node writes a span's times in, so that an
// owed event written again is the same event byte for byte, whether its
// span was read from the sensor or from the saved cursor.
func canonUTC(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func laterUTC(a, b string) string {
	if parseUTC(b).After(parseUTC(a)) {
		return b
	}
	return a
}

func parseUTC(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func num(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

func (l *Link) now() time.Time {
	if l.opt.Now != nil {
		return l.opt.Now().UTC()
	}
	return time.Now().UTC()
}

// frame acts on one frame after the hello, and returns a close reason or
// "".
func (l *Link) frame(ctx context.Context, cn *conn, b []byte) string {
	fs, err := netobs.DecodeFromSensorIn(b, cn.hello.Schema)
	cn.tickFrame = fs.Type == netobs.TypeTick
	switch fs.Type {
	case netobs.TypeSensorHello:
		return netobs.CloseHello // a second hello
	case netobs.TypeTick:
		if err != nil {
			return netobs.CloseTick
		}
		return l.tick(ctx, cn, fs.Tick)
	}
	var sensor, run, seq string
	switch {
	case fs.Heartbeat != nil:
		sensor, run, seq = fs.Heartbeat.SensorID, fs.Heartbeat.RunID, fs.Heartbeat.Seq
	case fs.Observation != nil:
		sensor, run, seq = fs.Observation.SensorID, fs.Observation.RunID, fs.Observation.Seq
	}
	n, perr := strconv.ParseUint(seq, 10, 64)
	// A record refused before its seq can be read (decode, schema, type)
	// takes no seq; the tick's sent_seq covers it (CH-14).
	if (fs.Heartbeat == nil && fs.Observation == nil) || slices.Contains(netobs.Codes(err), netobs.CodeDecode) ||
		!netobs.ValidUUID(run) || perr != nil || n == 0 {
		l.refusedFinal(cn, codeOf(err))
		return ""
	}
	pl := netobs.PlaceRecord(cn.hello, cn.l, cn.cur.Taken, sensor, run, n)
	switch pl.Place {
	case netobs.PlaceRun:
		return netobs.CloseRun
	case netobs.PlaceSeq:
		l.refuse(RefusedSeq) // at or below L: never final, T is past it already
		return ""
	}
	cn.l, cn.cur.G = pl.L, cn.cur.G+pl.Gap
	if pl.Gap > 0 {
		cn.pending = true
		l.notFromStart(cn)
	}
	switch {
	case pl.Place == netobs.PlaceSensorID:
		l.takeRefused(cn, n, RefusedSensorID)
		return ""
	case pl.Place == netobs.PlaceDuplicate:
		l.mu.Lock()
		l.stats.Dropped[RefusedDuplicate]++
		l.mu.Unlock()
		return ""
	case err != nil:
		l.takeRefused(cn, n, codeOf(err))
		return ""
	case fs.Heartbeat != nil:
		return l.heartbeat(ctx, cn, fs.Heartbeat, n)
	}
	return l.observation(ctx, cn, fs.Observation, n)
}

// refusedFinal counts a refusal that takes no seq: the totals rise, and
// the tick's sent_seq makes its seq a gap.
func (l *Link) refusedFinal(cn *conn, reason string) {
	l.notFromStart(cn) // a seq the tick will count as a gap
	l.refuse(reason)
	cn.cur.Refused++
	cn.pending = true
}

// notFromStart: a loss is declared or a seq missed, so the run is no
// longer seen from its start (CH-27).
func (l *Link) notFromStart(cn *conn) {
	cn.fromStart, l.startRun = false, ""
}

// takeRefused counts record n refused and moves T past it once the totals
// are saved with it (CH-17).
func (l *Link) takeRefused(cn *conn, n uint64, reason string) {
	l.refusedFinal(cn, reason)
	cn.cur.Taken = max(cn.cur.Taken, n)
}

func (l *Link) heartbeat(ctx context.Context, cn *conn, h *netobs.Heartbeat, n uint64) string {
	if h.Coverage.ConfigDigest != cn.cur.Digest {
		l.takeRefused(cn, n, string(netobs.CodeConflict)) // CH-32
		return ""
	}
	l.mu.Lock()
	prev := l.stats.Heartbeat
	l.mu.Unlock()
	judged := prev
	if judged == nil {
		// After a node start: the packets kept with W (K-1).
		judged = l.keptHeartbeat(h)
	}
	if err := h.Follows(judged); err != nil {
		l.takeRefused(cn, n, RefusedCounterDecrease)
		return ""
	}
	// The step check before lateness is judged and W and R take the
	// receipt's time (D3's N1 on #774); a save that fails closes before the
	// heartbeat is taken, so its resend follows.
	if err := l.stepAtReceipt(ctx); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: W and R moved by a step of the node's clock were not saved: %v", l.cfg.SensorID, err))
		return netobs.CloseStore
	}
	late := l.late(cn, h.AtUTC, true) // counted; a heartbeat is never a skew sample (CH-23)
	if l.heartbeatRaise(h) {
		if r := l.saveFloor(ctx, cn); r != "" {
			return r
		}
	}
	if d := h.Counters.DropsChannel; d > cn.cur.D {
		cn.cur.D = d
		l.notFromStart(cn)
	}
	if l.opt.Health != nil {
		// A baseline save that fails closes before the heartbeat is
		// taken here, so its resend follows (D4's B2 on #747).
		if r := l.baselines(ctx, cn, h, prev, n); r != "" {
			return r
		}
	}
	l.mu.Lock()
	l.stats.Heartbeat, l.stats.LastSeq = h, n
	l.stats.Heartbeats++
	l.stats.HeartbeatMono = l.opt.Monotonic()
	l.mu.Unlock()
	cn.cur.Taken, cn.pending = max(cn.cur.Taken, n), true
	l.place(cn, h, late)
	if degraded(h.Coverage) {
		l.cmu.Lock()
		l.giveWay(ctx, false)
		l.syncHold()
		l.cmu.Unlock()
	}
	return ""
}

// transmitBaselineFirst is a test seam, false in the node: the control
// that saves frames_outgoing's baseline before the run file takes the
// raise.
var transmitBaselineFirst bool

// baselines judges heartbeat n against the run's durable baselines
// (section 1.8): sensor-transmitted at a non-zero frames_outgoing with
// none held or any rise, written to the run file before the baseline that
// holds it is saved; sensor-egress-absent; and the rises of every counter
// made due as sensor.counters, a capture loss among them. The rise of a
// capture counter, and of frames_outgoing, is judged against the cursor's
// baseline; any other counter's against the previous heartbeat taken in
// this process, or the run total with none. A baseline changed is saved
// at once, before the heartbeat is acted on; a save that fails closes
// store, and the heartbeat is resent.
func (l *Link) baselines(ctx context.Context, cn *conn, h *netobs.Heartbeat, prev *netobs.Heartbeat, n uint64) string {
	hl, cur := l.opt.Health, cn.cur
	next := cur.clone()
	vals := counterValues(&h.Counters)
	durable := map[string]*uint64{"frames_outgoing": cur.FramesOutgoing, "drops_holder": cur.DropsHolder,
		"frames_overlong": cur.FramesOverlong, "drops_driver": cur.DropsDriver}
	var pv map[string]*uint64
	if prev != nil {
		pv = counterValues(&prev.Counters)
	}
	rises := map[string]uint64{}
	for name, v := range vals {
		base, ok := durable[name]
		if !ok && pv != nil {
			base = pv[name]
		}
		if r := rise(v, base); r > 0 {
			rises[name] = r
		}
	}
	for _, f := range []struct {
		to **uint64
		v  *uint64
	}{{&next.FramesOutgoing, h.Counters.FramesOutgoing}, {&next.DropsHolder, h.Counters.DropsHolder},
		{&next.FramesOverlong, h.Counters.FramesOverlong}, {&next.DropsDriver, h.Counters.DropsDriver}} {
		if f.v != nil {
			v := *f.v
			*f.to = &v
		}
	}
	l.egress(cn, h, next)
	next.Taken = max(next.Taken, n)
	transmit := rises["frames_outgoing"] > 0
	detail := fmt.Sprintf("sensor %s: run %s's frames_outgoing is %d", h.SensorID, h.RunID, deref(h.Counters.FramesOutgoing))
	if transmit && !transmitBaselineFirst {
		if err := hl.transmit(ctx, detail); err != nil {
			next.FramesOutgoing = cur.FramesOutgoing // not durable: the next heartbeat raises again
		}
	}
	// The capture loss is held, and the run file written within its
	// minute, before the cursor takes the new totals (section 1.8).
	hl.counters(ctx, countersKey(cn.en.Began), h.RunID, rises, captureTotals(next))
	if !sameBaselines(cur, next) {
		if err := l.saveCursor(ctx, next); err != nil {
			l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: the baselines of run %s were not saved: %v", h.SensorID, h.RunID, err))
			return netobs.CloseStore
		}
		cn.saved, cn.lastSave = next.Taken, l.opt.Monotonic()
	}
	if transmit && transmitBaselineFirst {
		_ = hl.transmit(ctx, detail)
	}
	cn.cur = next
	return ""
}

func deref(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

func sameBaselines(a, b *Cursor) bool {
	return a.Egress == b.Egress && sameTotals(captureTotals(a), captureTotals(b)) &&
		sameTotals([3]*uint64{a.FramesOutgoing}, [3]*uint64{b.FramesOutgoing})
}

// egress judges egress_check against the run's baseline (CH-27): a run's
// first heartbeat seen from its start sets it, carried or not, and raises
// nothing; with none held otherwise, a heartbeat that omits the field
// raises sensor-egress-absent, as does one that drops a field carried, or
// states it absent. It raises once a run while the link runs.
func (l *Link) egress(cn *conn, h *netobs.Heartbeat, next *Cursor) {
	why := ""
	switch {
	case h.EgressCheck == "absent":
		why = "states egress_check absent"
		next.Egress = EgressCarried // carried, so a later omission reads as absent (CH-27; D4's B1 on #747)
	case h.EgressCheck != "":
		if next.Egress != EgressCarried {
			next.Egress = EgressCarried
		}
	case next.Egress == EgressCarried:
		why = "dropped egress_check within the run"
	case next.Egress == "" && cn.fromStart:
		next.Egress = EgressOmitted // never carried: status shows unknown
	case next.Egress == "":
		why = "omits egress_check, and the node holds no baseline from the run's start"
	}
	if why != "" && l.egressRun != h.RunID {
		l.egressRun = h.RunID
		l.raise(AlarmEgressAbsent, fmt.Sprintf("sensor %s: run %s %s", h.SensorID, h.RunID, why))
	}
}

// observeFault is a test seam, nil in the node: it runs between a record's
// cursor encode and its commit, where a run file write from another
// goroutine can land.
var observeFault func()

// observation stores record n, with node.lost when spans are unmarked
// (CH-40), and the cursor in the same commit (CH-17).
func (l *Link) observation(ctx context.Context, cn *conn, o *netobs.Observation, n uint64) string {
	if o.Coverage.ConfigDigest != cn.cur.Digest {
		l.takeRefused(cn, n, string(netobs.CodeConflict)) // CH-32
		return ""
	}
	// The flush runs before the record's cursor is built, so what a
	// release moved is either in cn.cur now or in l.moved after the encode,
	// where commitOne folds it; never taken by a flush after the encode and
	// then written back (D6's B2 on #742).
	if l.hold.on() && !l.flush(ctx, cn, true) {
		return netobs.CloseStore // T through n-1 is saved before n can be held
	}
	marked := cn.cur.clone()
	lost := markLost(marked)
	marked.Taken = max(marked.Taken, n)
	l.cmu.Lock()
	marked.WriteNo = max(marked.WriteNo, l.writeNo)
	l.cmu.Unlock()
	mb, err := l.encode(marked)
	if err != nil {
		// A cursor that cannot be encoded is the node's fault, not the
		// record's refusal: the record is not taken, T stays, nothing is
		// acked, and the connection closes (D6's B1 (ii) on #732).
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: the position with record %d of run %s was not saved: %v", o.SensorID, n, o.RunID, err))
		return netobs.ClosePositionNotSaved
	}
	f := &inflight{run: o.RunID, seq: n, cursor: mb, marked: marked}
	l.cmu.Lock()
	l.inflight = f
	l.cmu.Unlock()
	l.mu.Lock()
	l.stats.LastSeq = n
	l.mu.Unlock()
	if observeFault != nil {
		observeFault()
	}
	l.observe(ctx, o, n, lost, l.late(cn, o.MadeUTC, false))
	l.cmu.Lock()
	l.inflight = nil
	l.cmu.Unlock()
	switch f.outcome {
	case outStoreError:
		return netobs.CloseStore // not final: T stays, the record is resent
	case outCommitted:
		cn.cur, cn.saved, cn.pending = f.marked, f.marked.Taken, false // with what releases moved (commitOne)
	case outDuplicate:
		// A release disposed of n after it was placed: a duplicate by the
		// position saved now (section 1.4 item 4). T moves at the next fold.
	case outRefused:
		cn.cur.Refused++
		cn.cur.Taken, cn.pending = n, true
	case outDropped:
		cn.cur.Dropped++
		cn.cur.Taken, cn.pending = n, true
	default: // held, or committed in a release: final, and stored
		marked.Taken = n
		cn.cur, cn.pending = marked, true
	}
	return ""
}

// markLost puts every unmarked window in node.lost, at most MaxLostSpans,
// prior's first (CH-40). A window cut to nothing writes no entry.
func markLost(c *Cursor) []netobs.Span {
	var out []netobs.Span
	mark := func(list []HeldSpan) {
		for i := range list {
			s := &list[i]
			if s.Marked || len(out) == netobs.MaxLostSpans {
				continue
			}
			s.Marked = true
			if parseUTC(s.CutUTC).After(parseUTC(s.FromUTC)) {
				out = append(out, netobs.Span{FromUTC: s.FromUTC, ToUTC: s.CutUTC})
			}
		}
	}
	if c.Prior != nil {
		mark(c.Prior.Spans)
	}
	mark(c.Spans)
	return out
}

// tick acts on an accepted tick (CH-8, CH-15, CH-40).
func (l *Link) tick(ctx context.Context, cn *conn, t *netobs.Tick) string {
	now := l.opt.Monotonic()
	v := netobs.JudgeTick(netobs.TickState{Hello: cn.hello, Last: cn.lastTick, Since: now - cn.tickAt,
		Spans: cn.cur.stated(), Ds: cn.cur.Ds}, t)
	switch {
	case v.SensorID:
		l.refuse(RefusedSensorID)
		return netobs.CloseTick
	case v.Close != "":
		return v.Close
	case v.Early:
		l.mu.Lock()
		l.conn.TickEarly++
		l.mu.Unlock()
		return ""
	}
	if err := l.stepAtReceipt(ctx); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: W and R moved by a step of the node's clock were not saved: %v", l.cfg.SensorID, err))
		return netobs.CloseStore
	}
	cn.lastTick, cn.tickAt = t, now
	raised, onset := l.sample(t.SensorUTC, false, cn.held)
	raised = l.spansRaise(t.Lost) || raised
	if onset {
		l.skewOnset(ctx)
	}
	sent, drops := num(t.SentSeq), num(t.DropsChannel)
	if drops > cn.cur.D {
		l.notFromStart(cn) // a declared loss (D6's B4 on #747)
	}
	cn.cur.D, cn.cur.NewestSeq = max(cn.cur.D, drops), num(t.NewestSeq)
	cn.sent = max(cn.sent, sent)
	if from := max(cn.l, cn.cur.Taken); sent > from {
		cn.cur.G += sent - from
		l.notFromStart(cn)
	}
	cn.l = max(cn.l, sent)
	cn.cur.Taken = max(cn.cur.Taken, cn.l)
	cn.pending = true
	if v.SpansWidened {
		next := cn.cur.clone()
		var cuts, opened uint64
		next.Spans, next.Ds = admit(next.Spans, t.Lost, t.SensorUTC, l.now(), &cuts, &opened), drops
		if err := l.saveCursor(ctx, next); err != nil {
			// Nothing admitted that is not saved with its D (D6's N4 item 5
			// on #742: raised as at the hello).
			l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: the spans of run %s were not saved: %v", t.SensorID, t.RunID, err))
			return netobs.CloseStore
		}
		l.mu.Lock()
		l.conn.SpansCut += cuts
		l.mu.Unlock()
		cn.cur, cn.saved, cn.pending, cn.lastSave = next, next.Taken, false, now
		l.lostOpened(t.SensorID, t.RunID, opened)
		l.owedInRun(ctx, cn)
		raised = false // saved with the spans
	}
	l.checkGap(cn.cur)
	if raised {
		return l.saveFloor(ctx, cn)
	}
	return ""
}

// saveFloor saves the cursor at once after the capture floor rose, so M
// carries it (section 1.5). A save that fails closes store, as a
// baseline's does.
func (l *Link) saveFloor(ctx context.Context, cn *conn) string {
	if err := l.saveCursor(ctx, cn.cur); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: the capture floor was not saved: %v", l.cfg.SensorID, err))
		return netobs.CloseStore
	}
	cn.saved, cn.pending, cn.lastSave = cn.cur.Taken, false, l.opt.Monotonic()
	return ""
}

// WriteOwed writes what the cursor still owes the health stream (a prior's
// sensor.run-loss, each owed span's lost gap) through Options.Owed, then
// clears the marks with a cursor save. The node calls it at its start; a
// kill between the two writes gives an event twice, never not at all
// (CH-16, CH-40). While a connection is live it does nothing: that
// connection writes them.
func (l *Link) WriteOwed(ctx context.Context) error {
	l.curMu.Lock()
	defer l.curMu.Unlock()
	l.guard.mu.Lock()
	live := l.guard.live != nil
	l.guard.mu.Unlock()
	if live {
		return nil // the live connection writes what it admits, and its own cursor is newer
	}
	defer l.closeCursor()
	cur, err := l.openCursor(ctx)
	if err != nil || cur == nil {
		return err
	}
	o, n := owedOf(cur)
	if gaps := len(o.Spans) + priorGaps(o.Prior); gaps > 0 {
		// The lost gaps still owed stand, as at their admission (S-10 (d)).
		l.raise(AlarmRecordsLost, fmt.Sprintf("sensor %s: run %s declares lost records; %d lost coverage gaps are owed at the start", l.cfg.SensorID, cur.RunID, gaps))
	}
	err = l.writeOwed(ctx, &conn{cur: cur})
	if err == nil && n > 0 && l.opt.Health != nil {
		l.opt.Health.startCopy(uint64(n))
	}
	return err
}

func (l *Link) writeOwed(ctx context.Context, cn *conn) error {
	c := cn.cur
	o, n := owedOf(c)
	if n == 0 || l.opt.Owed == nil {
		return nil
	}
	if err := l.opt.Owed(ctx, o); err != nil {
		return err
	}
	next := c.clone()
	if next.Prior != nil {
		next.Prior.Owed = false
		for i := range next.Prior.Spans {
			next.Prior.Spans[i].Owed = false
		}
	}
	for i := range next.Spans {
		next.Spans[i].Owed = false
	}
	if err := l.saveCursor(ctx, next); err != nil {
		return err
	}
	cn.cur, cn.saved, cn.pending = next, next.Taken, false
	return nil
}

func priorGaps(p *HeldPrior) int {
	if p == nil {
		return 0
	}
	n := 0
	for _, s := range p.Spans {
		if s.Owed {
			n++
		}
	}
	return n
}

// outcome is what became of the record the 0.2 path is taking.
type outcome int

const (
	outFinal      outcome = iota // held, or committed in a release
	outCommitted                 // committed with the cursor
	outRefused                   // refused, counted
	outDropped                   // dropped, counted
	outStoreError                // a store error that is not final (CH-17)
	outDuplicate                 // released since it was placed: a duplicate
)

// inflight is the record the 0.2 path is taking: its commit carries the
// cursor, encoded before the record is taken, and its outcome is noted.
// cmu guards it.
type inflight struct {
	run     string
	seq     uint64
	cursor  []byte
	marked  *Cursor // the cursor encoded in cursor
	outcome outcome
}

// mine reports whether hr is the record in flight.
func (f *inflight) mine(hr HeldRecord) bool { return f != nil && f.run == hr.RunID && f.seq == hr.Seq }
