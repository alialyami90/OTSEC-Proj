package forward

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
)

// Stream is one C5 stream the target forwards, with the store interfaces of
// the database that holds it (A5 hands them over; D2-1). The audit stream
// lives in its own database, so each stream carries its own interfaces.
type Stream struct {
	ID      store.StreamID
	Audit   bool // the audit stream: sealed C8 bytes, rendered with RenderAudit
	Outbox  store.Outbox
	Cursors store.CursorStore
	// Index finds where a new best-effort target starts: the first event
	// committed in its replay window (C6). Required for an event stream of
	// a best-effort target; unused otherwise.
	Index store.CommitIndex
}

// HealthSink commits a platform health event the forwarder raises
// (forward.text-omitted, forward.too-large, forward.unreachable). The sink
// builds the pending C4 event (node, Config.HealthStream, receive time) and
// returns its key once the commit has returned.
type HealthSink interface {
	Emit(ctx context.Context, h event.Health) (store.Key, error)
}

// Config is one forwarding target.
type Config struct {
	Target  *syslog.Target
	Streams []Stream
	// HealthStream is the stream HealthSink commits to. It must be one of
	// Streams, so the forward.* events reach this collector and a
	// too-large event can be released.
	HealthStream store.StreamID
	// Dial opens the connection to the collector: DialTLS for relp-tls,
	// DialTCP for a lab-only plain relp target.
	Dial   func(ctx context.Context) (net.Conn, error)
	Health HealthSink
	// ResponseTimeout bounds the wait for the oldest outstanding
	// transaction; zero means syslog.DefaultRELPResponseTimeout.
	ResponseTimeout time.Duration
	// Poll is how long an idle session waits before reading the outbox
	// again; zero means one second.
	Poll time.Duration
	// RetryMin and RetryMax bound the wait between sessions after a failed
	// one; zero means 1 s and 60 s.
	RetryMin, RetryMax time.Duration
}

// ErrConfig is returned by New and ClientTLS for a configuration the
// forwarder refuses.
var ErrConfig = errors.New("forward: invalid configuration")

// Forwarder sends the committed events of its streams to one RELP target.
// See the package doc for the rules.
type Forwarder struct {
	cfg      Config
	consumer store.ConsumerID
	maxTXNR  uint64 // syslog.MaxTXNR; lowered by tests

	// What this process has already reported, so a session that ends and
	// reconnects does not raise the same health event again (A6 #89).
	// Used only by the goroutine running Run.
	tooLarge map[store.Key]store.Key      // held event -> its forward.too-large
	omitted  map[store.Key]bool           // events reported as forward.text-omitted
	skipped  map[store.StreamID]store.Seq // highest seq reported as forward.unreachable

	mu     sync.Mutex
	status Status
}

// Status is what the node shows about the target.
type Status struct {
	Streams map[store.StreamID]StreamStatus
	// LastConfirmed is when a transaction was last confirmed, zero if never
	// in this process. The node raises forward.unreachable for a required
	// target from it.
	LastConfirmed time.Time
	// Confirmed counts confirmed transactions in this process.
	Confirmed uint64
	// LastErr is why the last session ended, nil while none has failed.
	LastErr error
}

// StreamStatus is one stream of the target.
type StreamStatus struct {
	Cursor  store.Seq // last position saved for this target
	Blocked string    // why the stream is held, "" when it is not
}

// New checks the configuration. Only mode A targets are accepted: relp-tls,
// or plain relp, which syslog.Target.Validate allows only best-effort with
// a lab-only acknowledgement.
func New(cfg Config) (*Forwarder, error) {
	t := cfg.Target
	if t == nil {
		return nil, fmt.Errorf("%w: no target", ErrConfig)
	}
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if t.Mode() != syslog.ModeA {
		return nil, fmt.Errorf("%w: target %s uses %s; this forwarder sends mode A (RELP) only", ErrConfig, t.Name, t.Transport)
	}
	if cfg.Dial == nil || cfg.Health == nil || len(cfg.Streams) == 0 {
		return nil, fmt.Errorf("%w: dial, health sink and streams are required", ErrConfig)
	}
	seen := map[store.StreamID]bool{}
	audits, health := 0, false
	for _, s := range cfg.Streams {
		if !s.ID.Valid() || seen[s.ID] || s.Outbox == nil || s.Cursors == nil {
			return nil, fmt.Errorf("%w: stream %q", ErrConfig, s.ID)
		}
		seen[s.ID] = true
		if s.Audit {
			audits++
		} else {
			health = health || s.ID == cfg.HealthStream
			if t.Class == syslog.ClassBestEffort && s.Index == nil {
				return nil, fmt.Errorf("%w: stream %q of best-effort target %s needs a commit index", ErrConfig, s.ID, t.Name)
			}
		}
	}
	if audits > 1 || (audits == 1) != t.Audit {
		return nil, fmt.Errorf("%w: target audit %v with %d audit streams", ErrConfig, t.Audit, audits)
	}
	if !health {
		return nil, fmt.Errorf("%w: health stream %q is not one of the target's event streams", ErrConfig, cfg.HealthStream)
	}
	if cfg.ResponseTimeout <= 0 {
		cfg.ResponseTimeout = syslog.DefaultRELPResponseTimeout
	}
	if cfg.Poll <= 0 {
		cfg.Poll = time.Second
	}
	if cfg.RetryMin <= 0 {
		cfg.RetryMin = time.Second
	}
	if cfg.RetryMax < cfg.RetryMin {
		cfg.RetryMax = max(60*time.Second, cfg.RetryMin)
	}
	f := &Forwarder{cfg: cfg, consumer: store.ConsumerID(t.Name), maxTXNR: syslog.MaxTXNR,
		tooLarge: map[store.Key]store.Key{}, omitted: map[store.Key]bool{}, skipped: map[store.StreamID]store.Seq{},
		status: Status{Streams: map[store.StreamID]StreamStatus{}}}
	for _, s := range cfg.Streams {
		f.status.Streams[s.ID] = StreamStatus{}
	}
	return f, nil
}

// Status returns a copy of the target's status.
func (f *Forwarder) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.status
	out.Streams = make(map[store.StreamID]StreamStatus, len(f.status.Streams))
	for id, s := range f.status.Streams {
		out.Streams[id] = s
	}
	return out
}

func (f *Forwarder) update(fn func(*Status)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.status)
}

func (f *Forwarder) setStream(id store.StreamID, fn func(*StreamStatus)) {
	f.update(func(s *Status) {
		x := s.Streams[id]
		fn(&x)
		s.Streams[id] = x
	})
}

// Run forwards until ctx ends, and then returns ctx.Err(). A session that
// fails is closed and a new one starts after a backoff, which resets once a
// session has confirmed something. Nothing after the saved cursors is
// skipped.
func (f *Forwarder) Run(ctx context.Context) error {
	wait := f.cfg.RetryMin
	for {
		before := f.Status().Confirmed
		err := f.session(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f.update(func(s *Status) { s.LastErr = err })
		if f.Status().Confirmed > before {
			wait = f.cfg.RetryMin
		}
		if err == nil {
			continue // a clean end at the last TXNR: reopen at once
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		wait = min(wait*2, f.cfg.RetryMax)
	}
}

// inflight is one sent transaction.
type inflight struct {
	txnr   uint64
	stream int
	key    store.Key
	sentAt time.Time
}

// held is a stream stopped at seq. A too-large event carries the key of
// the forward.too-large event that releases it; anything else has none
// and stays held.
type held struct {
	seq     store.Seq
	release *store.Key
}

// session is one RELP session: open, send, confirm, save cursors.
type session struct {
	f      *Forwarder
	ctx    context.Context
	conn   net.Conn
	win    *syslog.Window
	buf    []byte // response bytes not parsed yet, at most MaxRELPFrameLen
	rbuf   []byte
	txnr   uint64
	flight []inflight
	// Per stream:
	queue   [][]store.Stored // read from the outbox, not sent yet
	read    []store.Seq      // the last seq read into the queue
	saved   []store.Seq      // the cursor persisted for this target
	hold    []*held
	stopped bool // TXNRs used up: drain, close, reopen
}

func (f *Forwarder) session(ctx context.Context) error {
	conn, err := f.cfg.Dial(ctx)
	if err != nil {
		return fmt.Errorf("forward: dial %s: %w", f.cfg.Target.Name, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	n := len(f.cfg.Streams)
	s := &session{f: f, ctx: ctx, conn: conn, rbuf: make([]byte, syslog.MaxRELPFrameLen),
		queue: make([][]store.Stored, n), read: make([]store.Seq, n), saved: make([]store.Seq, n),
		hold: make([]*held, n)}
	if err := s.loadCursors(); err != nil {
		return err
	}
	if err := s.open(); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.release(); err != nil {
			return err
		}
		if err := s.fill(); err != nil {
			return err
		}
		if s.stopped && len(s.flight) == 0 {
			// Best effort: the session ends either way, and nothing
			// depends on the collector's answer.
			_ = s.write([]byte(strconv.FormatUint(s.txnr+1, 10) + " close 0\n"))
			return nil
		}
		wait := f.cfg.Poll
		if len(s.flight) > 0 {
			wait = time.Until(s.flight[0].sentAt.Add(f.cfg.ResponseTimeout))
		}
		if err := s.receive(wait); err != nil {
			return err
		}
	}
}

func (s *session) loadCursors() error {
	for i, st := range s.f.cfg.Streams {
		cs, err := st.Cursors.LoadCursors(s.ctx, st.ID)
		if err != nil {
			return fmt.Errorf("forward: load cursors of %s: %w", st.ID, err)
		}
		found := false
		for _, c := range cs {
			if c.Consumer == s.f.consumer && c.Stream == st.ID {
				s.saved[i], s.read[i], found = c.Through, c.Through, true
			}
		}
		// A new required target starts at the first retained event, so it
		// receives everything still held. A new best-effort target starts
		// at the first event in its replay window (C6-A5-2); the audit
		// stream has no window and starts at the first retained record.
		t := s.f.cfg.Target
		if !found && t.Class == syslog.ClassBestEffort && !st.Audit {
			from := time.Now().Add(-time.Duration(t.ReplaySeconds) * time.Second)
			after, err := st.Index.LastCommittedBy(s.ctx, st.ID, from)
			if err != nil {
				return fmt.Errorf("forward: find the replay window of %s: %w", st.ID, err)
			}
			s.read[i] = after
		}
		s.f.setStream(st.ID, func(x *StreamStatus) { x.Cursor = s.saved[i] })
	}
	return nil
}

// open sends the RELP open command as transaction 1 and waits for its
// answer, which must offer commands=syslog (C6 Window).
func (s *session) open() error {
	s.txnr = 1
	s.win = syslog.NewWindow(s.f.cfg.Target.RELPWindow, 1)
	offers := "relp_version=0\nrelp_software=otsec\ncommands=syslog"
	if err := s.write([]byte(fmt.Sprintf("1 open %d %s\n", len(offers), offers))); err != nil {
		return fmt.Errorf("forward: open: %w", err)
	}
	r, err := s.next(s.f.cfg.ResponseTimeout)
	if errors.Is(err, errTimeout) {
		return fmt.Errorf("forward: open: no response within %s", s.f.cfg.ResponseTimeout)
	}
	if err != nil {
		return fmt.Errorf("forward: open: %w", err)
	}
	if _, err := s.win.Answer(r); err != nil {
		return fmt.Errorf("forward: open: %w", err)
	}
	// RELP version 0 is the only one this forwarder speaks, and librelp
	// offers it; a collector that offers another is refused (A2 #89).
	if !slices.ContainsFunc(bytes.Split(r.Data, []byte("\n")), func(l []byte) bool { return string(l) == "relp_version=0" }) {
		return fmt.Errorf("forward: open: collector does not offer relp_version=0")
	}
	return nil
}

func (s *session) write(b []byte) error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.f.cfg.ResponseTimeout)); err != nil {
		return err
	}
	_, err := s.conn.Write(b)
	return err
}

// fill sends events, taking the streams in turn, until the window is full
// or no stream has anything it may send.
func (s *session) fill() error {
	for {
		progress := false
		for i := range s.f.cfg.Streams {
			if s.stopped || len(s.flight) >= s.f.cfg.Target.RELPWindow {
				return nil
			}
			ok, err := s.sendNext(i)
			if err != nil {
				return err
			}
			progress = progress || ok
		}
		if !progress {
			return nil
		}
	}
}

// peek returns the next event of stream i, reading the outbox when the
// queue is empty, and reports any seqs the outbox skipped.
func (s *session) peek(i int) (*store.Stored, error) {
	if len(s.queue[i]) == 0 {
		st := s.f.cfg.Streams[i]
		evs, err := st.Outbox.Read(s.ctx, st.ID, s.read[i], s.f.cfg.Target.RELPWindow)
		if err != nil {
			return nil, fmt.Errorf("forward: read %s: %w", st.ID, err)
		}
		for _, ev := range evs {
			seq := ev.Key.Seq
			if ev.Key.Stream != st.ID || seq <= s.read[i] {
				return nil, fmt.Errorf("forward: outbox of %s returned %s after %d", st.ID, ev.Key, s.read[i])
			}
			// A new required target reads from 0 and takes the first
			// retained event as its start, so nothing is reported. Past
			// a cursor or a best-effort window start, a jump is a loss.
			if seq > s.read[i]+1 && s.read[i] > 0 {
				if err := s.skipped(st.ID, s.read[i]+1, seq-1); err != nil {
					return nil, err
				}
			}
			s.read[i] = seq
		}
		s.queue[i] = evs
	}
	if len(s.queue[i]) == 0 {
		return nil, nil
	}
	return &s.queue[i][0], nil
}

// skipped reports seqs pruned before this target confirmed them: a
// best-effort target's window passed. Reported, never hidden (C6-A5).
func (s *session) skipped(stream store.StreamID, first, last store.Seq) error {
	if last <= s.f.skipped[stream] {
		return nil // reported by an earlier session
	}
	first = max(first, s.f.skipped[stream]+1)
	_, err := s.f.cfg.Health.Emit(s.ctx, event.Health{Type: event.HealthForwardUnreachable, Details: map[string]string{
		"target": s.f.cfg.Target.Name, "stream": string(stream),
		"first_skipped": strconv.FormatUint(first, 10), "last_skipped": strconv.FormatUint(last, 10),
		"reason": "pruned before this target confirmed them",
	}})
	if err != nil {
		return fmt.Errorf("forward: report skipped %s %d-%d: %w", stream, first, last, err)
	}
	s.f.skipped[stream] = last
	return nil
}

// sendNext sends the next event of stream i, if there is one it may send.
func (s *session) sendNext(i int) (bool, error) {
	if s.hold[i] != nil {
		return false, nil
	}
	ev, err := s.peek(i)
	if err != nil || ev == nil {
		return false, err
	}
	if s.txnr+2 > s.f.maxTXNR {
		s.stopped = true // keep the last TXNR for close
		return false, nil
	}
	msg, err := s.render(i, ev)
	if err != nil || msg == nil {
		return false, err
	}
	s.txnr++
	frame, err := syslog.FrameRELP(s.txnr, msg)
	if err != nil {
		return false, err
	}
	if err := s.win.Send(s.txnr); err != nil {
		return false, fmt.Errorf("forward: %w", err)
	}
	if err := s.write(frame); err != nil {
		return false, fmt.Errorf("forward: send: %w", err)
	}
	s.flight = append(s.flight, inflight{txnr: s.txnr, stream: i, key: ev.Key, sentAt: time.Now()})
	s.queue[i] = s.queue[i][1:]
	return true, nil
}

// render renders one stored record. It returns nil, nil when the record
// holds its stream.
func (s *session) render(i int, ev *store.Stored) ([]byte, error) {
	st := s.f.cfg.Streams[i]
	t := s.f.cfg.Target
	if st.Audit {
		msg, err := syslog.RenderAudit(ev.Event, t)
		if err != nil {
			// Never skipped, never cut: the audit cursor holds (D1-15).
			s.stop(i, ev.Key.Seq, nil, fmt.Sprintf("audit record %s cannot be rendered: %v", ev.Key, err))
			return nil, nil
		}
		return msg, nil
	}
	e, err := event.Decode(ev.Event)
	if err != nil {
		s.stop(i, ev.Key.Seq, nil, fmt.Sprintf("stored event %s does not decode: %v", ev.Key, err))
		return nil, nil
	}
	if e.ID != ev.Key {
		s.stop(i, ev.Key.Seq, nil, fmt.Sprintf("stored event %s carries ID %s", ev.Key, e.ID))
		return nil, nil
	}
	msg, out, err := syslog.Render(e, t)
	own := e.Health != nil && isForwardHealth(e.Health.Type)
	if err != nil {
		var se *syslog.Error
		if !errors.As(err, &se) || se.Code != syslog.CodeTooLarge || own || st.ID == s.f.cfg.HealthStream {
			// Only too-large has a release rule, and it needs a later
			// health event to be confirmed. A forward.* event would need
			// another about itself, and on the health stream the release
			// event would queue behind the event it releases.
			s.stop(i, ev.Key.Seq, nil, fmt.Sprintf("event %s cannot be rendered: %v", ev.Key, err))
			return nil, nil
		}
		key, ok := s.f.tooLarge[ev.Key]
		if !ok {
			key, err = s.f.cfg.Health.Emit(s.ctx, event.Health{Type: syslog.HealthTooLarge, Related: []event.EventID{ev.Key}, Details: map[string]string{
				"target": t.Name, "limit": strconv.Itoa(t.MaxMessageOctets),
			}})
			if err != nil {
				return nil, fmt.Errorf("forward: report too-large %s: %w", ev.Key, err)
			}
			s.f.tooLarge[ev.Key] = key
		}
		s.stop(i, ev.Key.Seq, &key, fmt.Sprintf("event %s does not fit %d octets; it is passed once %s is confirmed", ev.Key, t.MaxMessageOctets, key))
		return nil, nil
	}
	if (out.TextOmitted || out.SummaryDropped) && !own && !s.f.omitted[ev.Key] {
		if _, err := s.f.cfg.Health.Emit(s.ctx, event.Health{Type: event.HealthForwardTextOmitted, Related: []event.EventID{ev.Key}, Details: map[string]string{
			"target": t.Name, "text_omitted": strconv.FormatBool(out.TextOmitted), "summary_dropped": strconv.FormatBool(out.SummaryDropped),
		}}); err != nil {
			return nil, fmt.Errorf("forward: report text-omitted %s: %w", ev.Key, err)
		}
		s.f.omitted[ev.Key] = true
	}
	return msg, nil
}

func isForwardHealth(typ string) bool {
	switch typ {
	case event.HealthForwardTextOmitted, event.HealthForwardUnconfirmed, event.HealthForwardUnreachable, syslog.HealthTooLarge:
		return true
	}
	return false
}

func (s *session) stop(i int, seq store.Seq, release *store.Key, why string) {
	s.hold[i] = &held{seq: seq, release: release}
	s.f.setStream(s.f.cfg.Streams[i].ID, func(x *StreamStatus) { x.Blocked = why })
}

// release moves a stream held at a too-large event past it, once every
// earlier event of the stream and the forward.too-large event about it are
// confirmed by this target (C6 size rule).
func (s *session) release() error {
	for i, h := range s.hold {
		if h == nil || h.release == nil || s.inFlight(i) {
			continue
		}
		j := s.index(h.release.Stream)
		if j < 0 || s.saved[j] < h.release.Seq {
			continue
		}
		st := s.f.cfg.Streams[i]
		if err := st.Cursors.SaveCursor(s.ctx, store.Cursor{Consumer: s.f.consumer, Stream: st.ID, Through: h.seq}); err != nil {
			return fmt.Errorf("forward: save cursor %s: %w", st.ID, err)
		}
		s.saved[i], s.hold[i] = h.seq, nil
		s.f.confirmed(st.ID, h.seq)
		s.queue[i] = s.queue[i][1:]
		s.f.setStream(st.ID, func(x *StreamStatus) { x.Cursor, x.Blocked = h.seq, "" })
	}
	return nil
}

// inFlight reports whether stream i has a transaction not yet confirmed.
// Streams are sent in seq order and a held stream sends nothing, so when
// none is left every event before the held one is confirmed.
func (s *session) inFlight(i int) bool {
	for _, x := range s.flight {
		if x.stream == i {
			return true
		}
	}
	return false
}

// confirmed forgets what was reported about events of stream up to seq,
// which this target has now passed, so the sets stay small.
func (f *Forwarder) confirmed(stream store.StreamID, seq store.Seq) {
	for k := range f.omitted {
		if k.Stream == stream && k.Seq <= seq {
			delete(f.omitted, k)
		}
	}
	for k := range f.tooLarge {
		if k.Stream == stream && k.Seq <= seq {
			delete(f.tooLarge, k)
		}
	}
}

func (s *session) index(id store.StreamID) int {
	for i, st := range s.f.cfg.Streams {
		if st.ID == id {
			return i
		}
	}
	return -1
}

// receive waits up to wait for one response, applies it to the window and
// saves the cursors it confirms. With transactions in flight, running out
// of time is the response timeout and ends the session (C6-A3-8).
func (s *session) receive(wait time.Duration) error {
	r, err := s.next(wait)
	if errors.Is(err, errTimeout) {
		if len(s.flight) > 0 {
			return fmt.Errorf("forward: no response to transaction %d within %s", s.flight[0].txnr, s.f.cfg.ResponseTimeout)
		}
		return nil
	}
	if err != nil {
		return err
	}
	through, err := s.win.Answer(r)
	if errors.Is(err, syslog.ErrRefused) {
		// Name the event, so a collector that refuses the same one on
		// every session (a receive limit below the target's, say) can be
		// found from Status without reading logs (A2 #89).
		for _, x := range s.flight {
			if x.txnr == r.TXNR {
				return fmt.Errorf("forward: collector refused %s (transaction %d): %w", x.key, x.txnr, err)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("forward: %w", err)
	}
	if through == 0 {
		return nil
	}
	upto := map[int]store.Seq{}
	k := 0
	for ; k < len(s.flight) && s.flight[k].txnr <= through; k++ {
		upto[s.flight[k].stream] = s.flight[k].key.Seq
	}
	s.flight = s.flight[k:]
	for i, seq := range upto {
		st := s.f.cfg.Streams[i]
		if err := st.Cursors.SaveCursor(s.ctx, store.Cursor{Consumer: s.f.consumer, Stream: st.ID, Through: seq}); err != nil {
			return fmt.Errorf("forward: save cursor %s: %w", st.ID, err)
		}
		s.saved[i] = seq
		s.f.confirmed(st.ID, seq)
		s.f.setStream(st.ID, func(x *StreamStatus) { x.Cursor = seq })
	}
	s.f.update(func(x *Status) { x.Confirmed += uint64(k); x.LastConfirmed = time.Now() })
	return nil
}

var errTimeout = errors.New("forward: read timeout")

// next returns the next RELP response, reading until one is complete or
// wait runs out (errTimeout). The buffer never holds more than
// syslog.MaxRELPFrameLen octets: ParseRELPResponse decides any frame that
// long, so a slow or hostile collector cannot grow it.
func (s *session) next(wait time.Duration) (syslog.RELPResponse, error) {
	deadline := time.Now().Add(max(wait, time.Millisecond))
	for {
		if len(s.buf) > 0 {
			r, n, err := syslog.ParseRELPResponse(s.buf, s.win.Outstanding)
			if err == nil {
				s.buf = append(s.buf[:0], s.buf[n:]...)
				return r, nil
			}
			if !errors.Is(err, syslog.ErrIncomplete) {
				return r, fmt.Errorf("forward: %w", err)
			}
			if len(s.buf) >= syslog.MaxRELPFrameLen {
				return r, fmt.Errorf("forward: response longer than %d octets", syslog.MaxRELPFrameLen)
			}
		}
		if err := s.conn.SetReadDeadline(deadline); err != nil {
			return syslog.RELPResponse{}, err
		}
		n, err := s.conn.Read(s.rbuf[:syslog.MaxRELPFrameLen-len(s.buf)])
		s.buf = append(s.buf, s.rbuf[:n]...)
		if n > 0 {
			continue
		}
		var ne net.Error
		switch {
		case errors.As(err, &ne) && ne.Timeout():
			return syslog.RELPResponse{}, errTimeout
		case errors.Is(err, io.EOF):
			return syslog.RELPResponse{}, fmt.Errorf("forward: collector closed the connection with %d transactions outstanding", len(s.flight))
		case err != nil:
			return syslog.RELPResponse{}, err
		}
	}
}
