package node

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
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
	// confirmed nothing for UnreachableAfter.
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

	// Alarms already raised for the current condition, so Check raises
	// each once until the condition clears. Used only by Check.
	unreachable bool
	held        map[c5.StreamID]string
}

// NewForwarding builds a forwarder for every target of the runtime's
// configuration. Each target's TLS references are resolved first
// (Config.TargetTLS), so a missing or bad reference, or a client
// certificate whose name is not the target's permitted_peer, stops the node
// before anything is sent; nothing falls back to another reference (D2-12).
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
		tg := &target{t: t, held: map[c5.StreamID]string{}, since: rt.opt.Now()}
		cfg := forward.Config{Target: t, HealthStream: HealthStream, Health: healthSink{rt}}
		for _, c := range consumers {
			if string(c.ID) != t.Name {
				continue
			}
			cfg.Streams = append(cfg.Streams, forward.Stream{ID: c.Stream, Audit: c.Stream == AuditStream,
				Outbox: liveStore{rt, c.Stream}, Cursors: liveStore{rt, c.Stream}})
			tg.streams = append(tg.streams, c.Stream)
		}
		sort.Slice(tg.streams, func(i, j int) bool { return tg.streams[i] < tg.streams[j] })
		switch t.Transport {
		case syslog.TransportRELPTLS:
			tlsCfg, err := rt.cfg.TargetTLS(t)
			if err != nil {
				return nil, err
			}
			cfg.Dial = forward.DialTLS(t, tlsCfg, DialTimeout)
		default:
			dial, err := forward.DialTCP(t, DialTimeout)
			if err != nil {
				return nil, fmt.Errorf("target %s: %w", t.Name, err)
			}
			cfg.Dial = dial
		}
		if tg.f, err = forward.New(cfg); err != nil {
			return nil, fmt.Errorf("target %s: %w", t.Name, err)
		}
		fw.targets = append(fw.targets, tg)
	}
	return fw, nil
}

// Run runs every forwarder until ctx ends.
func (fw *Forwarding) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, tg := range fw.targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tg.f.Run(ctx)
		}()
	}
	wg.Wait()
}

// Check copies each forwarder's Status into node status and raises
// AlarmForwardUnreachable and AlarmForwardHeld, each once per condition.
// The node calls it before every Tick.
func (fw *Forwarding) Check(ctx context.Context) {
	now := fw.rt.opt.Now()
	for _, tg := range fw.targets {
		st := tg.f.Status()
		ts := TargetStatus{Class: string(tg.t.Class), LastConfirmed: st.LastConfirmed.UTC(), Confirmed: st.Confirmed,
			Streams: map[string]TargetStreamState{}}
		if st.LastConfirmed.IsZero() {
			ts.LastConfirmed = time.Time{}
		}
		if st.LastErr != nil {
			ts.LastErr = st.LastErr.Error()
		}
		waiting := false
		for _, id := range tg.streams {
			ss := st.Streams[id]
			state := TargetStreamState{Cursor: uint64(ss.Cursor), Blocked: ss.Blocked}
			if db := fw.rt.Store(id); db != nil {
				if last, err := db.LastCommitted(ctx, id); err == nil {
					state.Last = uint64(last)
					waiting = waiting || last > ss.Cursor
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
		fw.rt.opt.Status.SetTarget(tg.t.Name, ts)

		last := st.LastConfirmed
		if last.Before(tg.since) {
			last = tg.since
		}
		down := tg.t.Class == syslog.ClassRequired && waiting && now.Sub(last) >= UnreachableAfter
		switch {
		case down && !tg.unreachable:
			tg.unreachable = true
			detail := fmt.Sprintf("events waiting and nothing confirmed for %s", now.Sub(last).Round(time.Second))
			if st.LastErr != nil {
				detail += "; last session: " + st.LastErr.Error()
			}
			fw.rt.opt.Status.RaiseTarget(tg.t.Name, AlarmForwardUnreachable, detail)
			fw.rt.health(ctx, event.HealthForwardUnreachable, map[string]string{"target": tg.t.Name})
		case !down:
			tg.unreachable = false
		}
	}
}

// healthSink commits the forwarder's health events on platform/health and
// returns each one's key once its commit has returned.
type healthSink struct{ rt *Runtime }

func (h healthSink) Emit(ctx context.Context, he event.Health) (c5.Key, error) {
	log := h.rt.Log(HealthStream)
	if log == nil {
		return c5.Key{}, errors.New("node: the health stream's database is not open")
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
