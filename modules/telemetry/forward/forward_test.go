package forward

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
)

// fill commits n copies of row 8 on the SER stream.
func (r *rig) fill(n int) {
	e := row8(r.t)
	for range n {
		r.m.commit(r.t, serStream, e)
	}
}

// delivered reports whether every committed event of every stream has been
// acknowledged and the cursors have reached the last seq.
func (r *rig) delivered() bool {
	got := map[string]bool{}
	for _, id := range eids(r.t, r.srv.Acked()) {
		got[id] = true
	}
	for _, st := range []store.StreamID{serStream, hlStream} {
		for _, k := range r.m.keys(st) {
			if !got[k] {
				return false
			}
		}
		r.m.mu.Lock()
		last := r.m.last[st]
		r.m.mu.Unlock()
		if r.m.cursor(st) != last {
			return false
		}
	}
	return true
}

// checkNoLoss checks that every committed event was acknowledged at least
// once, and returns how many acknowledgements were duplicates.
func (r *rig) checkNoLoss() int {
	r.t.Helper()
	ids := eids(r.t, r.srv.Acked())
	seen := map[string]int{}
	for _, id := range ids {
		seen[id]++
	}
	for _, st := range []store.StreamID{serStream, hlStream} {
		for _, k := range r.m.keys(st) {
			if seen[k] == 0 {
				r.t.Errorf("%s never acknowledged", k)
			}
		}
	}
	return len(ids) - len(seen)
}

func TestForwardsEveryEventOnce(t *testing.T) {
	r := newRig(t, nil, nil)
	r.fill(100)
	r.run(r.delivered, nil)
	if dup := r.checkNoLoss(); dup != 0 {
		t.Errorf("%d duplicates with no fault", dup)
	}
	if n := r.srv.Conns(); n != 1 {
		t.Errorf("%d connections, want 1", n)
	}
	if errs := r.srv.Errors(); len(errs) > 0 {
		t.Errorf("receiver errors: %v", errs)
	}
	// Oldest first, as committed.
	ids := eids(t, r.srv.Acked())
	if !slices.Equal(ids, r.m.keys(serStream)) {
		t.Errorf("order: %v", ids[:5])
	}
	// Each message is the C6 rendering.
	m := r.srv.Acked()[0].Data
	if !strings.Contains(string(m), ` v="otsec.syslog/0.2" `) || !strings.Contains(string(m), ` evc="simulated" `) {
		t.Errorf("message %s", m)
	}
}

// P2-A4 acceptance: the receiver closes mid-batch, the forwarder resumes
// from the cursor and loses nothing.
func TestReceiverClosesMidBatch(t *testing.T) {
	for _, at := range []int{1, 5, 37, 99} {
		t.Run(strconv.Itoa(at), func(t *testing.T) {
			r := newRig(t, func(n int, _ relptest.Message) relptest.Action {
				if n == at || n == at+40 {
					return relptest.Close
				}
				return relptest.Ack
			}, nil)
			r.fill(120)
			r.run(r.delivered, nil)
			dup := r.checkNoLoss()
			if r.srv.Conns() < 2 {
				t.Errorf("%d connections; the close was not exercised", r.srv.Conns())
			}
			// Only what was in flight at a close is sent again: at most
			// one window per close.
			if dup > 2*r.tg.RELPWindow {
				t.Errorf("%d duplicates, more than the windows in flight", dup)
			}
			// Each new session starts right after a saved cursor: the
			// first message of every connection after the first is an
			// event that was never acknowledged before it or is the
			// first unacknowledged one.
			checkResume(t, r.srv.Acked())
			if errs := r.srv.Errors(); len(errs) > 0 {
				t.Errorf("receiver errors: %v", errs)
			}
		})
	}
}

// checkResume checks that within each connection the SER seqs run without
// a gap, and each connection starts at or before the seq after the highest
// one acknowledged on earlier connections.
func checkResume(t *testing.T, ms []relptest.Message) {
	t.Helper()
	ids := eids(t, ms)
	var high store.Seq
	conn, prev := 0, store.Seq(0)
	for i, m := range ms {
		k, err := event.ParseEventID(ids[i])
		if err != nil {
			t.Fatal(err)
		}
		if k.Stream != serStream {
			continue
		}
		if m.Conn != conn {
			if k.Seq > high+1 {
				t.Errorf("connection %d starts at %d after %d was acknowledged: skipped", m.Conn, k.Seq, high)
			}
			conn, prev = m.Conn, k.Seq-1
		}
		if k.Seq != prev+1 {
			t.Errorf("connection %d: %d after %d", m.Conn, k.Seq, prev)
		}
		prev = k.Seq
		high = max(high, k.Seq)
	}
}

// Every way a session can end without a 200 OK: the forwarder reconnects
// and sends the unconfirmed transactions again.
func TestSessionEndsAndResends(t *testing.T) {
	for name, act := range map[string]relptest.Action{
		"refused": relptest.Refuse, "serverclose": relptest.ServerClose, "silent": relptest.Silent,
		"answered twice": relptest.AckTwice,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(n int, _ relptest.Message) relptest.Action {
				if n == 10 {
					return act
				}
				return relptest.Ack
			}, nil)
			r.cfg.ResponseTimeout = 300 * time.Millisecond
			r.fill(30)
			f := r.run(r.delivered, nil)
			r.checkNoLoss()
			if r.srv.Conns() < 2 {
				t.Errorf("%d connections, want a reconnect", r.srv.Conns())
			}
			if f.Status().LastErr == nil {
				t.Error("no session error recorded")
			}
		})
	}
}

// The cursor moves only on a confirmed acknowledgement: a collector that
// acknowledges 5 and then goes silent leaves the cursor at 5.
func TestCursorOnlyOnAck(t *testing.T) {
	r := newRig(t, func(n int, _ relptest.Message) relptest.Action {
		if n > 5 {
			return relptest.Silent
		}
		return relptest.Ack
	}, nil)
	r.cfg.ResponseTimeout = 200 * time.Millisecond
	r.fill(20)
	f := r.run(func() bool { return r.srv.Conns() >= 3 }, nil)
	if c := r.m.cursor(serStream); c != 5 {
		t.Errorf("cursor %d, want 5", c)
	}
	if c := f.Status().Streams[serStream].Cursor; c != 5 {
		t.Errorf("status cursor %d, want 5", c)
	}
	for _, s := range r.m.saves {
		if s.Stream == serStream && s.Through > 5 {
			t.Errorf("saved %d", s.Through)
		}
	}
}

func TestResumesFromSavedCursor(t *testing.T) {
	r := newRig(t, nil, nil)
	r.fill(60)
	if err := r.m.SaveCursor(t.Context(), store.Cursor{Consumer: "siem-a", Stream: serStream, Through: 50}); err != nil {
		t.Fatal(err)
	}
	r.run(func() bool { return r.m.cursor(serStream) == 60 }, nil)
	ids := eids(t, r.srv.Acked())
	want := event.EventID{NodeID: node, Stream: serStream, Seq: 51}.String()
	if ids[0] != want {
		t.Errorf("first sent %s, want %s", ids[0], want)
	}
	if len(ids) != 10 {
		t.Errorf("%d sent, want 10", len(ids))
	}
}

// A best-effort target's window passed: the outbox jumps, and the skipped
// range is reported as forward.unreachable and forwarded.
func TestSkippedRangeReported(t *testing.T) {
	r := newRig(t, nil, nil)
	r.fill(30)
	if err := r.m.SaveCursor(t.Context(), store.Cursor{Consumer: "siem-a", Stream: serStream, Through: 10}); err != nil {
		t.Fatal(err)
	}
	r.m.prune(serStream, 20)
	r.run(func() bool {
		return r.m.cursor(serStream) == 30 && r.m.cursor(hlStream) >= 1
	}, nil)
	var found bool
	for _, m := range r.srv.Acked() {
		s := string(m.Data)
		if strings.Contains(s, `htype="forward.unreachable"`) {
			found = strings.Contains(s, `first_skipped=11`) && strings.Contains(s, `last_skipped=20`)
		}
	}
	if !found {
		t.Error("no forward.unreachable for 11-20 was forwarded")
	}
}

// A message that fits only without its device text is sent, and
// forward.text-omitted names it.
func TestTextOmitted(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	r.fill(1)
	r.run(func() bool { return r.m.cursor(serStream) == 1 && r.m.cursor(hlStream) == 1 }, nil)
	acked := r.srv.Acked()
	if !strings.Contains(string(acked[0].Data), `dtext_omitted="size"`) {
		t.Errorf("message %s", acked[0].Data)
	}
	h := string(acked[1].Data)
	if !strings.Contains(h, `htype="forward.text-omitted"`) || !strings.Contains(h, `site-a-node1:sel751-feeder1/ser:1`) {
		t.Errorf("health %s", h)
	}
}

// An event that does not fit holds its stream until forward.too-large
// about it is confirmed; then the cursor passes it and the next is sent.
func TestTooLargeHeldThenPassed(t *testing.T) {
	other := store.StreamID("platform/other")
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	r.cfg.Streams = append(r.cfg.Streams, Stream{ID: other, Outbox: r.m, Cursors: r.m})
	big := r.m.commit(t, other, healthEvent(event.HealthSourceSilent, map[string]string{"note": strings.Repeat("x", 1200)}))
	r.m.commit(t, other, healthEvent(event.HealthSourceSilent, map[string]string{"note": "small"}))
	r.run(func() bool { return r.m.cursor(other) == 2 }, nil)
	var order []string
	for _, m := range r.srv.Acked() {
		s := string(m.Data)
		switch {
		case strings.Contains(s, `htype="forward.too-large"`):
			if !strings.Contains(s, big.String()) {
				t.Errorf("too-large does not name %s: %s", big, s)
			}
			order = append(order, "too-large")
		case strings.Contains(s, `note=small`):
			order = append(order, "next")
		case strings.Contains(s, big.String()):
			t.Errorf("the too-large event was sent: %s", s)
		}
	}
	if !slices.Equal(order, []string{"too-large", "next"}) {
		t.Errorf("order %v", order)
	}
}

// A record the forwarder cannot render holds its stream, never skips it.
func TestUnrenderableHolds(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) {
		tg.Name, tg.Audit, tg.MaxMessageOctets = "siem-a", true, syslog.MinAuditOctets
	})
	r.cfg.Streams = append(r.cfg.Streams, Stream{ID: auStream, Audit: true, Outbox: r.m, Cursors: r.m})
	r.m.commitRaw(auStream, []byte("not a sealed record"))
	r.fill(3)
	var f *Forwarder
	f = r.run(func() bool {
		return r.m.cursor(serStream) == 3 && f != nil && f.Status().Streams[auStream].Blocked != ""
	}, func(x *Forwarder) { f = x })
	if c := r.m.cursor(auStream); c != 0 {
		t.Errorf("audit cursor %d", c)
	}
	if b := f.Status().Streams[auStream].Blocked; !strings.Contains(b, "cannot be rendered") {
		t.Errorf("blocked %q", b)
	}
}

// At the last TXNR the session drains, closes and a new one continues.
func TestLastTXNRReopens(t *testing.T) {
	r := newRig(t, nil, nil)
	r.fill(25)
	r.run(r.delivered, func(f *Forwarder) { f.maxTXNR = 7 })
	if dup := r.checkNoLoss(); dup != 0 {
		t.Errorf("%d duplicates", dup)
	}
	if n := r.srv.Conns(); n < 5 {
		t.Errorf("%d connections, want one per 5 events", n)
	}
	if errs := r.srv.Errors(); len(errs) > 0 {
		t.Errorf("receiver errors: %v", errs)
	}
}

func TestNewRefuses(t *testing.T) {
	r := newRig(t, nil, nil)
	for name, mut := range map[string]func(*Config){
		"no target":           func(c *Config) { c.Target = nil },
		"no dial":             func(c *Config) { c.Dial = nil },
		"no health sink":      func(c *Config) { c.Health = nil },
		"health not streamed": func(c *Config) { c.HealthStream = "platform/elsewhere" },
		"duplicate stream":    func(c *Config) { c.Streams = append(c.Streams, c.Streams[0]) },
		"audit stream, not an audit target": func(c *Config) {
			c.Streams = append(c.Streams, Stream{ID: auStream, Audit: true, Outbox: r.m, Cursors: r.m})
		},
		"mode B target": func(c *Config) {
			t := *c.Target
			t.Transport, t.Class, t.Framing, t.RELPWindow, t.DurableAck, t.ReplaySeconds = syslog.TransportTLS, syslog.ClassBestEffort, "octet-counting", 0, nil, 3600
			c.Target = &t
		},
	} {
		c := r.cfg
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
