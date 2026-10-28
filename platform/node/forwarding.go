package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward"
	"otsec.local/otsec/platform/store"
)

// Forwarding alarms, raised from each forwarder's Status.
const (
	// AlarmForwardUnreachable: a required target has events waiting and has
	// confirmed nothing for UnreachableAfter, or has had no session open
	// for that long.
	AlarmForwardUnreachable = "forward-unreachable"
	// AlarmForwardHeld: a stream of the target is held (forward.Status
	// Blocked), so nothing after the held event reaches the target.
	AlarmForwardHeld = "forward-held"
)

// UnreachableAfter is how long a required target may have events waiting
// with no confirmation before the node raises AlarmForwardUnreachable. C6
// gives no period; 60 s follows the proposed V-S12 (a distinct health event
// within 60 s of the upstream going down). A1 and A6 own the final number.
const UnreachableAfter = 60 * time.Second

// CheckInterval is how often the node runs Forwarding.Check, so an outage
// is reported within UnreachableAfter plus this.
const CheckInterval = 10 * time.Second

// DialTimeout bounds each connection to a target, TLS handshake included.
const DialTimeout = 30 * time.Second

// Forwarding is the node's forwarders, one per C6 target (A4 #89).
type Forwarding struct {
	rt      *Runtime
	targets []*target
}

type target struct {
	t       *syslog.Target
	f       *forward.Forwarder
	streams []c5.StreamID
	since   time.Time // when this process started forwarding
	open    time.Time // when Check last saw a session open

	// Alarms already raised for the current condition, so Check raises
	// each once until the condition clears. Used only by Check.
	unreachable bool
	held        map[c5.StreamID]string

	// The client certificate of a relp-tls target (HR-13, D4-11). creds are
	// the references as loaded at start, and are never read again. tlsCfg
	// is the dial configuration, set once the certificate's period is
	// valid; ready is closed then, and Run does not start the forwarder
	// before. heldBack, notAfter and the two watches are used only by
	// Check (and NewForwarding before it).
	creds     *targetCreds
	tlsCfg    atomic.Pointer[tls.Config]
	ready     chan struct{}
	release   sync.Once
	heldBack  string
	notAfter  time.Time
	watch     certWatch
	heldWatch certWatch
}

// errHeldBack is the dial error of a target whose certificate period is not
// valid. The forwarder is not run while it holds, so this is a backstop:
// nothing is dialled.
var errHeldBack = errors.New("node: the target is held back: its client certificate is outside its validity period")

// NewForwarding builds a forwarder for every target of the runtime's
// configuration. Each target's TLS references are resolved first
// (Config.TargetTLS), so a missing or bad reference, or a client
// certificate whose name is not the target's permitted_peer, stops the node
// before anything is sent; nothing falls back to another reference (D2-12).
// The one exception is a client certificate outside its validity period
// (HR-13, D4-11): that target is held back with AlarmTargetHeldBack, its
// forwarder is not run, and the node and its other targets start.
// Forwarding.Check re-checks the loaded certificate and releases the target
// once the period is valid.
// The forwarders read each stream through a view that looks the open
// database up on every call, because Tick can replace a database's handle
// when it resumes one.
func NewForwarding(rt *Runtime) (*Forwarding, error) {
	fw := &Forwarding{rt: rt}
	consumers, err := rt.cfg.Consumers()
	if err != nil {
		return nil, err
	}
	for _, t := range rt.cfg.ForwardTargets() {
		tg := &target{t: t, held: map[c5.StreamID]string{}, since: rt.opt.Now(), ready: make(chan struct{})}
		cfg := forward.Config{Target: t, HealthStream: HealthStream, Health: healthSink{rt}}
		for _, c := range consumers {
			if string(c.ID) != t.Name {
				continue
			}
			// Index is used only by a best-effort target, to start a new
			// cursor at its replay window (A4 #94).
			cfg.Streams = append(cfg.Streams, forward.Stream{ID: c.Stream, Audit: c.Stream == AuditStream,
				Outbox: liveStore{rt, c.Stream}, Cursors: liveStore{rt, c.Stream}, Index: liveStore{rt, c.Stream}})
			tg.streams = append(tg.streams, c.Stream)
		}
		sort.Slice(tg.streams, func(i, j int) bool { return tg.streams[i] < tg.streams[j] })
		switch t.Transport {
		case syslog.TransportRELPTLS:
			if tg.creds, err = rt.cfg.loadTarget(t); err != nil {
				return nil, err
			}
			if tg.creds.client != nil {
				if _, tg.notAfter, err = leafPeriod(tg.creds.client); err != nil {
					return nil, fmt.Errorf("target %s: client credential: %w", t.Name, err)
				}
			}
			tlsCfg, err := forward.ClientTLS(t, tg.creds.roots, tg.creds.client)
			switch {
			case err == nil:
				tg.unhold(tlsCfg)
			case errors.Is(err, forward.ErrCertificatePeriod):
				tg.heldBack = periodState(tg.creds.client)
			default:
				return nil, err
			}
			cfg.Dial = func(ctx context.Context) (net.Conn, error) {
				c := tg.tlsCfg.Load()
				if c == nil {
					return nil, errHeldBack
				}
				return forward.DialTLS(t, c, DialTimeout)(ctx)
			}
		default:
			dial, err := forward.DialTCP(t, DialTimeout)
			if err != nil {
				return nil, fmt.Errorf("target %s: %w", t.Name, err)
			}
			cfg.Dial = dial
			tg.release.Do(func() { close(tg.ready) })
		}
		if tg.f, err = forward.New(cfg); err != nil {
			return nil, fmt.Errorf("target %s: %w", t.Name, err)
		}
		fw.targets = append(fw.targets, tg)
		fw.checkCert(tg)
	}
	return fw, nil
}

// unhold sets the target's dial configuration and lets its forwarder run.
func (tg *target) unhold(cfg *tls.Config) {
	tg.tlsCfg.Store(cfg)
	tg.release.Do(func() { close(tg.ready) })
}

// periodState is why client is outside its validity period now, by the
// clock the TLS check itself uses.
func periodState(client *tls.Certificate) string {
	nb, na, err := leafPeriod(client)
	if err != nil {
		return "expired"
	}
	return heldState(nb, na, time.Now())
}

// checkCert is the certificate half of Check for one target (D4-11). A
// target held back has its loaded certificate judged again, by the same
// clock as at start, and is released once the period is valid; until then
// AlarmTargetHeldBack is raised when the state changes and again every
// CertAlarmRepeat. A released target gets AlarmTargetCertExpiring at
// CertWarning before its client certificate ends, and, if it ends while the
// forwarder runs, again every CertAlarmRepeat: a running link is never
// stopped at expiry.
func (fw *Forwarding) checkCert(tg *target) {
	if tg.creds == nil || tg.creds.client == nil {
		return
	}
	now := fw.rt.opt.Now()
	if tg.heldBack != "" {
		cfg, err := forward.ClientTLS(tg.t, tg.creds.roots, tg.creds.client)
		switch {
		case err == nil:
			tg.heldBack, tg.heldWatch = "", certWatch{}
			tg.unhold(cfg)
		case errors.Is(err, forward.ErrCertificatePeriod):
			tg.heldBack = periodState(tg.creds.client)
			if tg.heldWatch.due(tg.heldBack, now) {
				nb, na, _ := leafPeriod(tg.creds.client)
				fw.rt.opt.Status.RaiseTarget(tg.t.Name, AlarmTargetHeldBack, fmt.Sprintf(
					"the node's client certificate for this target is %s: %s. The forwarder is not running, no connection is made and nothing is sent; its events wait in the store. It starts when the period is valid; to replace the certificate, replace %s.crt and .key and restart the node",
					tg.heldBack, periodDetail("it", nb, na), tg.t.TLS.ClientCredentialRef))
			}
			return
		default:
			// The same inputs passed or failed the period before; any other
			// refusal leaves the target held back.
			return
		}
	}
	state := certState(tg.notAfter, now)
	if !tg.watch.due(state, now) {
		return
	}
	end := "expires at"
	if state == "expired" {
		end = "expired at"
	}
	fw.rt.opt.Status.RaiseTarget(tg.t.Name, AlarmTargetCertExpiring, fmt.Sprintf(
		"the node's client certificate for this target %s %s. Replace %s.crt and .key and restart the node",
		end, tg.notAfter.UTC().Format(time.RFC3339), tg.t.TLS.ClientCredentialRef))
}

// Run runs every forwarder until ctx ends.
func (fw *Forwarding) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, tg := range fw.targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A held-back target runs no forwarder: no connection is made
			// until its certificate's period is valid (D4-11 item 10).
			select {
			case <-ctx.Done():
				return
			case <-tg.ready:
			}
			tg.f.Run(ctx)
		}()
	}
	wg.Wait()
}

// Check copies each forwarder's Status into node status and raises
// AlarmForwardUnreachable and AlarmForwardHeld, each once per condition.
// The node calls it before every Tick.
func (fw *Forwarding) Check(ctx context.Context) {
	for _, tg := range fw.targets {
		fw.check(ctx, tg, tg.f.Status())
	}
}

// check is Check for one target and its forwarder's status.
func (fw *Forwarding) check(ctx context.Context, tg *target, st forward.Status) {
	now := fw.rt.opt.Now()
	fw.checkCert(tg)
	ts := TargetStatus{Class: string(tg.t.Class), LastConfirmed: st.LastConfirmed.UTC(), Confirmed: st.Confirmed,
		Streams: map[string]TargetStreamState{}, HeldBack: tg.heldBack}
	if !tg.notAfter.IsZero() {
		ts.CertNotAfter = tg.notAfter.UTC()
	}
	if st.LastConfirmed.IsZero() {
		ts.LastConfirmed = time.Time{}
	}
	if st.LastErr != nil {
		ts.LastErr = st.LastErr.Error()
	}
	if !st.Open.IsZero() {
		ts.Open = st.Open.UTC()
		tg.open = now
	}
	ts.Unreported = st.Unreported
	if st.ReportErr != nil {
		ts.ReportErr = st.ReportErr.Error()
	}
	waiting := false
	for _, id := range tg.streams {
		ss := st.Streams[id]
		state := TargetStreamState{Cursor: uint64(ss.Cursor), Confirmed: uint64(ss.Confirmed), Blocked: ss.Blocked}
		if db := fw.rt.Store(id); db != nil {
			if last, err := db.LastCommitted(ctx, id); err == nil {
				state.Last = uint64(last)
				// What is waiting is what the target has not confirmed:
				// the cursor stays behind while a report about the stream
				// is owed (A4 #103). A held stream is reported as
				// forward-held; its events do not count as waiting (A4
				// #98).
				waiting = waiting || (last > ss.Confirmed && ss.Blocked == "")
			}
		}
		ts.Streams[string(id)] = state
		if ss.Blocked == "" {
			delete(tg.held, id)
		} else if tg.held[id] != ss.Blocked {
			tg.held[id] = ss.Blocked
			fw.rt.opt.Status.RaiseTarget(tg.t.Name, AlarmForwardHeld, fmt.Sprintf("stream %s held: %s", id, ss.Blocked))
		}
	}
	if fw.rt.opt.Status.SetTarget(tg.t.Name, ts) {
		// Written on a change, so health's counts are at most one check
		// behind, not one tick (A6 on #118).
		fw.rt.opt.Status.Write(string(fw.rt.cfg.NodeID))
	}

	// A required target is down when it has events waiting and has
	// confirmed nothing for UnreachableAfter, or when no session has been
	// open for that long, even with nothing waiting (A4 #94: Status.Open).
	confirmed := later(st.LastConfirmed, tg.since)
	opened := later(tg.open, tg.since)
	required := tg.t.Class == syslog.ClassRequired
	stalled := required && waiting && now.Sub(confirmed) >= UnreachableAfter
	closed := required && st.Open.IsZero() && now.Sub(opened) >= UnreachableAfter
	down := stalled || closed
	switch {
	case down && !tg.unreachable:
		tg.unreachable = true
		var detail string
		if stalled {
			detail = fmt.Sprintf("events waiting and nothing confirmed for %s", now.Sub(confirmed).Round(time.Second))
		} else {
			detail = fmt.Sprintf("no session open for %s", now.Sub(opened).Round(time.Second))
		}
		if st.LastErr != nil {
			detail += "; last session: " + st.LastErr.Error()
		}
		fw.rt.opt.Status.RaiseTarget(tg.t.Name, AlarmForwardUnreachable, detail)
		fw.rt.health(ctx, event.HealthForwardUnreachable, map[string]string{"target": tg.t.Name, "reason": detail})
	case !down:
		tg.unreachable = false
	}
}

func later(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

// healthSink commits the forwarder's health events on platform/health and
// returns each one's key once its commit has returned.
type healthSink struct{ rt *Runtime }

func (h healthSink) Emit(ctx context.Context, he event.Health) (c5.Key, error) {
	// The same rule as Runtime.health: nothing is appended in a mode that
	// does not accept events (A4 #98).
	_, log, mode := h.rt.view(h.rt.dbFor(HealthStream))
	if log == nil {
		return c5.Key{}, errors.New("node: the health stream's database is not open")
	}
	if !mode.AcceptsEvents() {
		return c5.Key{}, fmt.Errorf("node: the health stream's database is in mode %s, which accepts no events", mode)
	}
	rec, err := h.rt.healthEventRecord(HealthStream, he)
	if err != nil {
		return c5.Key{}, err
	}
	r, err := log.Append(ctx, rec)
	if err != nil {
		return c5.Key{}, err
	}
	return r.Key(), nil
}

// liveStore is one stream's C5 Outbox and CursorStore, looked up in the
// runtime on every call.
type liveStore struct {
	rt     *Runtime
	stream c5.StreamID
}

var (
	_ c5.Outbox      = liveStore{}
	_ c5.CursorStore = liveStore{}
	_ c5.CommitIndex = liveStore{}
)

func (l liveStore) db() (*store.DB, error) {
	if db := l.rt.Store(l.stream); db != nil {
		return db, nil
	}
	return nil, fmt.Errorf("node: the database holding %s is not open", l.stream)
}

func (l liveStore) Read(ctx context.Context, stream c5.StreamID, after c5.Seq, max int) ([]c5.Stored, error) {
	db, err := l.db()
	if err != nil {
		return nil, err
	}
	return db.Read(ctx, stream, after, max)
}

func (l liveStore) ReadCapture(ctx context.Context, ref string) (c5.Capture, error) {
	db, err := l.db()
	if err != nil {
		return c5.Capture{}, err
	}
	return db.ReadCapture(ctx, ref)
}

func (l liveStore) ChainAnchor(ctx context.Context, stream c5.StreamID) (c5.ChainLink, error) {
	db, err := l.db()
	if err != nil {
		return c5.ChainLink{}, err
	}
	return db.ChainAnchor(ctx, stream)
}

func (l liveStore) LastCommitted(ctx context.Context, stream c5.StreamID) (c5.Seq, error) {
	db, err := l.db()
	if err != nil {
		return 0, err
	}
	return db.LastCommitted(ctx, stream)
}

func (l liveStore) LastCommittedBy(ctx context.Context, stream c5.StreamID, t time.Time) (c5.Seq, error) {
	db, err := l.db()
	if err != nil {
		return 0, err
	}
	return db.LastCommittedBy(ctx, stream, t)
}

func (l liveStore) FirstRetained(ctx context.Context, stream c5.StreamID) (c5.Seq, error) {
	db, err := l.db()
	if err != nil {
		return 0, err
	}
	return db.FirstRetained(ctx, stream)
}

func (l liveStore) SaveCursor(ctx context.Context, c c5.Cursor) error {
	db, err := l.db()
	if err != nil {
		return err
	}
	return db.SaveCursor(ctx, c)
}

func (l liveStore) LoadCursors(ctx context.Context, stream c5.StreamID) ([]c5.Cursor, error) {
	db, err := l.db()
	if err != nil {
		return nil, err
	}
	return db.LoadCursors(ctx, stream)
}
