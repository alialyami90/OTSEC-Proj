package forward

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
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
	maxOwed  int    // MaxOwed; lowered by tests

	// What this process has already reported, so a session that ends and
	// reconnects does not raise the same health event again (A6 #89).
	// Used only by the goroutine running Run.
	tooLarge map[store.Key]store.Key      // held event -> its forward.too-large
	omitted  map[store.Key]bool           // events reported as forward.text-omitted
	skipped  map[store.StreamID]store.Seq // highest seq reported as forward.unreachable
	// Health events the sink refused, oldest first, committed later
	// (retryOwed). Past MaxOwed only their number per type is kept, and
	// lostHold the lowest seq each stream must not pass for them.
	owed     []owed
	lost     map[string]int
	lostHold map[store.StreamID]store.Seq
	// The replay window start of each best-effort stream that has no
	// cursor yet, worked out once per process (A6 #94).
	start map[store.StreamID]store.Seq

	mu     sync.Mutex
	status Status
}

// Status is what the node shows about the target.
type Status struct {
	Streams map[store.StreamID]StreamStatus
	// LastConfirmed is when a transaction was last confirmed, zero if never
	// in this process. The node raises forward.unreachable for a required
	// target from it and from Open.
	LastConfirmed time.Time
	// Confirmed counts confirmed transactions in this process.
	Confirmed uint64
	// LastErr is why the last session ended, nil while none has failed.
	LastErr error
	// Open is when the collector answered the current session's open, zero
	// while no session is open. A required target with Open zero is down
	// even when nothing is waiting to be sent.
	Open time.Time
	// Unreported counts forward.* health events the HealthSink refused and
	// the forwarder still holds to commit; ReportErr is the sink's last
	// refusal. Both clear once every one is committed.
	Unreported int
	ReportErr  error
}

// MaxOwed is how many refused health events the forwarder keeps whole.
// Beyond it, it keeps only their number per type and, once the sink accepts
// again, commits one event per type stating how many went unreported.
const MaxOwed = 1024

// StreamStatus is one stream of the target.
type StreamStatus struct {
	Cursor store.Seq // last position saved for this target
	// Confirmed is the last position this target has confirmed, at least
	// Cursor. It is ahead of Cursor while a refused report about the
	// stream is owed (Status.Unreported), so the node compares the
	// stream's last seq with this, not Cursor, to tell what is waiting.
	Confirmed store.Seq
	Blocked   string // why the stream is held, "" when it is not
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
	f := &Forwarder{cfg: cfg, consumer: store.ConsumerID(t.Name), maxTXNR: syslog.MaxTXNR, maxOwed: MaxOwed,
		tooLarge: map[store.Key]store.Key{}, omitted: map[store.Key]bool{}, skipped: map[store.StreamID]store.Seq{},
		lost: map[string]int{}, lostHold: map[store.StreamID]store.Seq{}, start: map[store.StreamID]store.Seq{},
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
		f.retryOwed(ctx)
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
	retry   bool // too-large whose report was refused: render it again
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
	conf    []store.Seq      // confirmed by this target; saved lags it while a report is owed
	known   []bool           // the start is a cursor or a window start, so a jump past it is a loss
	hold    []*held
	stopped bool // TXNRs used up: drain, close, reopen
}

// prepare works out, once per process, where each event stream of a
// best-effort target without a cursor starts: after the last event
// committed before its replay window, or before the first retained event
// when none was (what was pruned before the target existed is not its
// loss). It saves that start as the cursor before the collector is even
// dialled, so a target that confirms nothing for a while, or cannot reach
// its collector, does not move its start forward and pass events over
// unreported (A6 #94). Events up to the start are outside the window, so
// saving it gives up nothing the target was owed.
func (f *Forwarder) prepare(ctx context.Context) error {
	t := f.cfg.Target
	if t.Class != syslog.ClassBestEffort {
		return nil
	}
	for _, st := range f.cfg.Streams {
		if _, ok := f.start[st.ID]; ok || st.Audit {
			continue
		}
		cs, err := st.Cursors.LoadCursors(ctx, st.ID)
		if err != nil {
			return fmt.Errorf("forward: load cursors of %s: %w", st.ID, err)
		}
		if i := slices.IndexFunc(cs, func(c store.Cursor) bool { return c.Consumer == f.consumer && c.Stream == st.ID }); i >= 0 {
			f.start[st.ID] = cs[i].Through
			continue
		}
		after, err := st.Index.LastCommittedBy(ctx, st.ID, time.Now().Add(-time.Duration(t.ReplaySeconds)*time.Second))
		if err == nil && after == 0 {
			var first store.Seq
			if first, err = st.Index.FirstRetained(ctx, st.ID); err == nil {
				if first > 0 {
					after = first - 1
				} else {
					after, err = st.Index.LastCommitted(ctx, st.ID)
				}
			}
		}
		if err != nil {
			return fmt.Errorf("forward: find the replay window of %s: %w", st.ID, err)
		}
		if after > 0 {
			if err := st.Cursors.SaveCursor(ctx, store.Cursor{Consumer: f.consumer, Stream: st.ID, Through: after}); err != nil {
				return fmt.Errorf("forward: save cursor %s: %w", st.ID, err)
			}
			f.setStream(st.ID, func(x *StreamStatus) { x.Cursor = after })
		}
		f.start[st.ID] = after
	}
	return nil
}

func (f *Forwarder) session(ctx context.Context) error {
	if err := f.prepare(ctx); err != nil {
		return err
	}
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
		conf: make([]store.Seq, n), known: make([]bool, n), hold: make([]*held, n)}
	if err := s.loadCursors(); err != nil {
		return err
	}
	if err := s.open(); err != nil {
		return err
	}
	f.update(func(x *Status) { x.Open = time.Now() })
	defer f.update(func(x *Status) { x.Open = time.Time{} })
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		f.retryOwed(ctx)
		if err := s.catchUp(); err != nil {
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
		s.conf[i], s.known[i] = s.saved[i], found
		s.f.setStream(st.ID, func(x *StreamStatus) { x.Confirmed = max(x.Confirmed, s.saved[i]) })
		// A new required target starts at the first retained event, so it
		// receives everything still held. A new best-effort target starts
		// at the first event in its replay window (C6-A5-2); the audit
		// stream has no window and starts at the first retained record.
		if !found && s.f.cfg.Target.Class == syslog.ClassBestEffort && !st.Audit {
			after, ok := s.f.start[st.ID]
			if !ok {
				return fmt.Errorf("forward: no window start for %s", st.ID)
			}
			s.read[i], s.conf[i], s.known[i] = after, after, true
			s.f.setStream(st.ID, func(x *StreamStatus) { x.Confirmed = max(x.Confirmed, after) })
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
			if seq > s.read[i]+1 && (s.read[i] > 0 || s.known[i]) {
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
	err := s.f.report(s.ctx, event.Health{Type: event.HealthForwardUnreachable, Details: map[string]string{
		"target": s.f.cfg.Target.Name, "stream": string(stream),
		"first_skipped": strconv.FormatUint(first, 10), "last_skipped": strconv.FormatUint(last, 10),
		"reason": "pruned before this target confirmed them",
	}}, stream, first)
	if err != nil {
		return err
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
				if s.ctx.Err() != nil {
					return nil, s.ctx.Err()
				}
				// The release needs this event's key, so the stream waits;
				// the other streams go on draining, which is what lets the
				// health stream accept it again. Retried at the next loop.
				s.hold[i] = &held{seq: ev.Key.Seq, retry: true}
				s.f.setStream(st.ID, func(x *StreamStatus) {
					x.Blocked = fmt.Sprintf("event %s does not fit %d octets, and forward.too-large about it was refused: %v", ev.Key, t.MaxMessageOctets, err)
				})
				return nil, nil
			}
			s.f.tooLarge[ev.Key] = key
		}
		s.stop(i, ev.Key.Seq, &key, fmt.Sprintf("event %s does not fit %d octets; it is passed once %s is confirmed", ev.Key, t.MaxMessageOctets, key))
		return nil, nil
	}
	if (out.TextOmitted || out.SummaryDropped) && !own && !s.f.omitted[ev.Key] {
		if err := s.f.report(s.ctx, event.Health{Type: event.HealthForwardTextOmitted, Related: []event.EventID{ev.Key}, Details: map[string]string{
			"target": t.Name, "text_omitted": strconv.FormatBool(out.TextOmitted), "summary_dropped": strconv.FormatBool(out.SummaryDropped),
		}}, ev.Key.Stream, ev.Key.Seq); err != nil {
			return nil, err
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
// save persists stream i's cursor at seq, or as far towards it as owed
// reports allow (Forwarder.limit).
func (s *session) save(i int, seq store.Seq) error {
	st := s.f.cfg.Streams[i]
	seq = s.f.limit(st.ID, seq)
	if seq <= s.saved[i] {
		return nil
	}
	if err := st.Cursors.SaveCursor(s.ctx, store.Cursor{Consumer: s.f.consumer, Stream: st.ID, Through: seq}); err != nil {
		return fmt.Errorf("forward: save cursor %s: %w", st.ID, err)
	}
	s.saved[i] = seq
	s.f.confirmed(st.ID, seq)
	s.f.setStream(st.ID, func(x *StreamStatus) { x.Cursor = seq })
	return nil
}

// catchUp saves the cursors that owed reports held back, once they are
// committed.
func (s *session) catchUp() error {
	for i := range s.conf {
		if s.conf[i] > s.saved[i] {
			if err := s.save(i, s.conf[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *session) release() error {
	for i, h := range s.hold {
		if h != nil && h.retry {
			s.hold[i] = nil // the next fill renders it and reports again
			continue
		}
		if h == nil || h.release == nil || s.inFlight(i) {
			continue
		}
		j := s.index(h.release.Stream)
		if j < 0 || s.conf[j] < h.release.Seq {
			continue
		}
		st := s.f.cfg.Streams[i]
		s.conf[i], s.hold[i] = h.seq, nil
		s.f.setStream(st.ID, func(x *StreamStatus) { x.Confirmed = max(x.Confirmed, h.seq) })
		if err := s.save(i, h.seq); err != nil {
			return err
		}
		s.queue[i] = s.queue[i][1:]
		s.f.setStream(st.ID, func(x *StreamStatus) { x.Blocked = "" })
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

// owed is a health event the sink refused. While it is owed, the cursor of
// stream stays below seq, the event or the first seq of the range it is
// about, so a restart sends that event again or finds that gap again and
// the report is raised again: a duplicate, never a lost one (A6 #94).
type owed struct {
	h      event.Health
	stream store.StreamID // "" when no cursor waits for it
	seq    store.Seq
}

// report commits a health event the forwarder raises about seq of stream:
// an event it still sends, or the first seq of a range it passed. A sink
// that refuses it (the health stream at quota, its database not open)
// does not stop forwarding: draining is what frees the store, and a
// forwarder stalled on its own report would never drain it. The event is
// kept and committed later, after the ones refused before it; Status
// counts it meanwhile, and the stream's cursor is not saved past seq until
// it is committed. The exception is the health stream of a required
// target: its cursor is what frees the health stream that refused the
// report, so holding it could keep that stream full for good. Only a
// cancelled ctx is returned.
func (f *Forwarder) report(ctx context.Context, h event.Health, stream store.StreamID, seq store.Seq) error {
	f.retryOwed(ctx)
	if len(f.owed) == 0 && len(f.lost) == 0 {
		_, err := f.cfg.Health.Emit(ctx, h)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f.update(func(s *Status) { s.ReportErr = err })
	}
	if f.cfg.Target.Class == syslog.ClassRequired && stream == f.cfg.HealthStream {
		stream = ""
	}
	if len(f.owed) < f.maxOwed {
		f.owed = append(f.owed, owed{h: h, stream: stream, seq: seq})
	} else {
		f.lost[h.Type]++
		if stream != "" && (f.lostHold[stream] == 0 || seq < f.lostHold[stream]) {
			f.lostHold[stream] = seq
		}
	}
	f.update(func(s *Status) { s.Unreported++ })
	return ctx.Err()
}

// retryOwed commits the refused health events in order, stopping at the
// first the sink still refuses, then one summary per type for those past
// maxOwed.
func (f *Forwarder) retryOwed(ctx context.Context) {
	for len(f.owed) > 0 {
		if _, err := f.cfg.Health.Emit(ctx, f.owed[0].h); err != nil {
			f.update(func(s *Status) { s.ReportErr = err })
			return
		}
		f.owed = f.owed[1:]
		f.update(func(s *Status) { s.Unreported-- })
	}
	for _, typ := range slices.Sorted(maps.Keys(f.lost)) {
		n := f.lost[typ]
		if _, err := f.cfg.Health.Emit(ctx, event.Health{Type: typ, Details: map[string]string{
			"target": f.cfg.Target.Name, "unreported": strconv.Itoa(n),
			"reason": "the health stream refused them while the forwarder held " + strconv.Itoa(f.maxOwed) + " others",
		}}); err != nil {
			f.update(func(s *Status) { s.ReportErr = err })
			return
		}
		delete(f.lost, typ)
		f.update(func(s *Status) { s.Unreported -= n })
	}
	clear(f.lostHold)
	f.update(func(s *Status) { s.ReportErr = nil })
}

// limit is the highest cursor stream may be saved at, up to seq, while
// reports about it are owed.
func (f *Forwarder) limit(stream store.StreamID, seq store.Seq) store.Seq {
	hold := f.lostHold[stream]
	for _, o := range f.owed {
		if o.stream == stream && (hold == 0 || o.seq < hold) {
			hold = o.seq
		}
	}
	if hold > 0 && seq >= hold {
		return hold - 1
	}
	return seq
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
		s.conf[i] = seq
		s.f.setStream(s.f.cfg.Streams[i].ID, func(x *StreamStatus) { x.Confirmed = max(x.Confirmed, seq) })
		if err := s.save(i, seq); err != nil {
			return err
		}
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
