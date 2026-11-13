package forward

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
)

// snStream stands for a sensor's stream, carried by a target's second
// session (D5's note section 1.9 item 1, F10; P4-4-F27 step 1).
const snStream = store.StreamID("sensor/s1/alerts")

// second returns the configuration of the rig target's second session over
// streams, beside the main session in r.cfg.
func (r *rig) second(streams ...Stream) Config {
	c := r.cfg
	c.Streams, c.HealthCursors = streams, r.m
	return c
}

// unopened is a stream whose database is not open: every read fails.
type unopened struct{ *memStore }

func (unopened) Read(context.Context, store.StreamID, store.Seq, int) ([]store.Stored, error) {
	return nil, errors.New("database not open")
}

func TestNewSecondSession(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) { tg.Audit, tg.MaxMessageOctets = true, syslog.MinAuditOctets })
	sn := Stream{ID: snStream, Outbox: r.m, Cursors: r.m}
	// An audit target's second session carries no audit stream and no
	// health stream: the main session keeps both.
	if _, err := New(r.second(sn)); err != nil {
		t.Fatalf("second session refused: %v", err)
	}
	for name, c := range map[string]Config{
		"with the health stream": r.second(sn, Stream{ID: hlStream, Outbox: r.m, Cursors: r.m}),
		"with an audit stream":   r.second(sn, Stream{ID: auStream, Audit: true, Outbox: r.m, Cursors: r.m}),
		"no health stream named": func() Config { c := r.second(sn); c.HealthStream = ""; return c }(),
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A too-large event of the second session is passed only once the main
// session's cursor on the health stream reaches its forward.too-large
// event, and the second session saves its cursor under the target's name.
// One health event is committed first, so forward.too-large is seq 2 and
// this target's cursor held at 1 pins the boundary (D6's B1 on #662).
func TestSecondSessionTooLargeWaitsForHealthCursor(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	r.m.commit(t, hlStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": "before"}))
	big := r.m.commit(t, snStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": strings.Repeat("x", 1200)}))
	r.m.commit(t, snStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": "small"}))
	r.cfg = r.second(Stream{ID: snStream, Outbox: r.m, Cursors: r.m})
	var f *Forwarder
	var heldSince time.Time
	saved := false
	early := func() bool {
		sent := slices.ContainsFunc(r.srv.Acked(), func(m relptest.Message) bool { return strings.Contains(string(m.Data), "note=small") })
		if c := r.m.cursor(snStream); c != 0 || sent {
			t.Errorf("passed before the main session confirmed forward.too-large: cursor %d, next event sent %v", c, sent)
			return true
		}
		return false
	}
	r.run(func() bool {
		if saved {
			return r.m.cursor(snStream) == 2
		}
		if early() {
			return true
		}
		if f == nil || !strings.Contains(f.Status().Streams[snStream].Blocked, "does not fit") {
			return false
		}
		if heldSince.IsZero() {
			heldSince = time.Now()
			// Another target's consumer has confirmed forward.too-large;
			// this target has confirmed only the event before it.
			for _, c := range []store.Cursor{{Consumer: "siem-b", Stream: hlStream, Through: 2}, {Consumer: "siem-a", Stream: hlStream, Through: 1}} {
				if err := r.m.SaveCursor(context.Background(), c); err != nil {
					t.Fatal(err)
				}
			}
		}
		if time.Since(heldSince) < 300*time.Millisecond {
			return false // several loops of the session, with this target's cursor one short of forward.too-large
		}
		// The main session confirms forward.too-large and saves its cursor.
		if err := r.m.SaveCursor(context.Background(), store.Cursor{Consumer: "siem-a", Stream: hlStream, Through: 2}); err != nil {
			t.Fatal(err)
		}
		saved = true
		return false
	}, func(x *Forwarder) { f = x })
	for _, m := range r.srv.Acked() {
		if strings.Contains(string(m.Data), big.String()) && !strings.Contains(string(m.Data), `htype="forward.too-large"`) {
			t.Errorf("the too-large event was sent: %s", m.Data)
		}
	}
	if n := r.healthCount(syslog.HealthTooLarge); n != 1 {
		t.Errorf("%d forward.too-large events, want 1", n)
	}
}

// The main session and a second session of one target, against one
// collector: the main session delivers forward.too-large, and only then
// does the second pass the event it is about.
func TestSecondSessionReleasedByMainSession(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	r.fill(3)
	big := r.m.commit(t, snStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": strings.Repeat("x", 1200)}))
	r.m.commit(t, snStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": "small"}))
	sec, err := New(r.second(Stream{ID: snStream, Outbox: r.m, Cursors: r.m}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	end := make(chan error, 1)
	go func() { end <- sec.Run(ctx) }()
	r.run(func() bool { return r.delivered() && r.m.cursor(snStream) == 2 }, nil)
	cancel()
	<-end
	var order []string
	for _, m := range r.srv.Acked() {
		s := string(m.Data)
		switch {
		case strings.Contains(s, `htype="forward.too-large"`) && strings.Contains(s, big.String()):
			order = append(order, "too-large")
		case strings.Contains(s, "note=small"):
			order = append(order, "next")
		}
	}
	if !slices.Equal(order, []string{"too-large", "next"}) {
		t.Errorf("order %v", order)
	}
}

// F10 at the forwarder: a second session whose stream cannot be read fails
// on its own, and the main session goes on delivering. The control is the
// one session of main's code, carrying that stream too, which delivers
// nothing.
func TestSecondSessionFailureLeavesMainSession(t *testing.T) {
	r := newRig(t, nil, nil)
	r.fill(5)
	r.m.commit(t, hlStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": "health"}))
	bad := Stream{ID: snStream, Outbox: unopened{r.m}, Cursors: r.m}
	sec, err := New(r.second(bad))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	end := make(chan error, 1)
	go func() { end <- sec.Run(ctx) }()
	r.run(func() bool { return r.delivered() && sec.Status().LastErr != nil }, nil)
	cancel()
	<-end
	if err := sec.Status().LastErr; !strings.Contains(err.Error(), "database not open") {
		t.Errorf("second session's error %v", err)
	}

	// Control: one session over every stream, the unreadable one included.
	c := newRig(t, nil, nil)
	c.fill(5)
	c.m.commit(t, hlStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": "health"}))
	c.cfg.Streams = append(c.cfg.Streams, Stream{ID: snStream, Outbox: unopened{c.m}, Cursors: c.m})
	one, err := New(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = one.Run(ctx)
	if ser, hl := c.m.cursor(serStream), c.m.cursor(hlStream); ser != 0 || hl != 0 {
		t.Errorf("control: one session over an unreadable stream still confirmed something (SER cursor %d, health cursor %d)", ser, hl)
	}
}

// failingCursors is a health stream whose database is not open: every
// LoadCursors fails.
type failingCursors struct{ *memStore }

func (failingCursors) LoadCursors(context.Context, store.StreamID) ([]store.Cursor, error) {
	return nil, errors.New("health database not open")
}

// A failed read of the health stream's cursors ends the second session's
// attempt and keeps its too-large event held: the next event is not sent,
// LastErr names the failed load, and forward.too-large is raised once over
// every attempt (D6's B2 on #662).
func TestSecondSessionHealthCursorReadFails(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	r.m.commit(t, snStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": strings.Repeat("x", 1200)}))
	r.m.commit(t, snStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": "small"}))
	r.cfg = r.second(Stream{ID: snStream, Outbox: r.m, Cursors: r.m})
	r.cfg.HealthCursors = failingCursors{r.m}
	var f *Forwarder
	r.run(func() bool {
		if c := r.m.cursor(snStream); c != 0 {
			return true
		}
		return f != nil && r.srv.Conns() >= 3 && f.Status().LastErr != nil
	}, func(x *Forwarder) { f = x })
	sent := slices.ContainsFunc(r.srv.Acked(), func(m relptest.Message) bool { return strings.Contains(string(m.Data), "note=small") })
	if c := r.m.cursor(snStream); c != 0 || sent {
		t.Errorf("passed on a failed health-cursor read: cursor %d, next event sent %v", c, sent)
	}
	if err := f.Status().LastErr; err == nil || !strings.Contains(err.Error(), "load cursors of platform/health") {
		t.Errorf("LastErr %v, want the failed load", err)
	}
	if n := r.healthCount(syslog.HealthTooLarge); n != 1 {
		t.Errorf("%d forward.too-large events over %d sessions, want 1", n, r.srv.Conns())
	}
}

// countingCursors counts the reads of the health stream's cursors.
type countingCursors struct {
	*memStore
	n atomic.Int64
}

func (c *countingCursors) LoadCursors(ctx context.Context, stream store.StreamID) ([]store.Cursor, error) {
	c.n.Add(1)
	return c.memStore.LoadCursors(ctx, stream)
}

// While an event is held, the second session reads the health stream's
// cursors at most once per Poll, however fast its other streams drain
// (D6's B3 on #662, D1's option (a)).
func TestSecondSessionHealthCursorReadsPerPoll(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	other := store.StreamID("sensor/s1/other")
	r.m.commit(t, snStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": strings.Repeat("x", 1200)}))
	for range 400 {
		r.m.commit(t, other, healthEvent(event.HealthSourceSilent, map[string]string{"note": "drain"}))
	}
	hc := &countingCursors{memStore: r.m}
	r.cfg = r.second(Stream{ID: snStream, Outbox: r.m, Cursors: r.m}, Stream{ID: other, Outbox: r.m, Cursors: r.m})
	r.cfg.HealthCursors, r.cfg.Poll = hc, 200*time.Millisecond
	start := time.Now()
	r.run(func() bool { return r.m.cursor(other) == 400 }, nil)
	elapsed := time.Since(start)
	if bound := int64(elapsed/r.cfg.Poll) + 2; hc.n.Load() > bound {
		t.Errorf("%d reads of the health cursors in %s at Poll %s, want at most %d", hc.n.Load(), elapsed, r.cfg.Poll, bound)
	}
	if hc.n.Load() == 0 {
		t.Error("the health cursors were never read")
	}
}
