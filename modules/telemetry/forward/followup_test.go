package forward

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
)

// A new best-effort target starts at the first event committed in its
// replay window, not at the first retained event (C6-A5-2, A6 #89).
func TestBestEffortStartsAtWindow(t *testing.T) {
	srv, err := relptest.Start(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tg := newTarget(t, srv.Addr().Port, plainRELP) // replay_seconds 3600
	dial, err := DialTCP(tg, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m := newStore()
	e := row8(t)
	for range 10 {
		m.commitAt(t, serStream, e, time.Now().Add(-2*time.Hour))
	}
	for range 5 {
		m.commit(t, serStream, e)
	}
	r := &rig{t: t, m: m, srv: srv, tg: tg, cfg: Config{
		Target:       tg,
		Streams:      []Stream{{ID: serStream, Outbox: m, Cursors: m, Index: m}, {ID: hlStream, Outbox: m, Cursors: m, Index: m}},
		HealthStream: hlStream, Dial: dial, Health: sink{t: t, m: m},
		ResponseTimeout: 2 * time.Second, Poll: 10 * time.Millisecond, RetryMin: 5 * time.Millisecond,
	}}
	r.run(func() bool { return m.cursor(serStream) == 15 }, nil)
	ids := eids(t, srv.Acked())
	if want := (event.EventID{NodeID: node, Stream: serStream, Seq: 11}).String(); len(ids) != 5 || ids[0] != want {
		t.Errorf("sent %v, want the 5 events from %s", ids, want)
	}
	if n := r.healthCount(event.HealthForwardUnreachable); n != 0 {
		t.Errorf("%d forward.unreachable for events outside the window", n)
	}

	// A best-effort event stream must come with a commit index.
	c := r.cfg
	c.Streams = []Stream{{ID: serStream, Outbox: m, Cursors: m}, {ID: hlStream, Outbox: m, Cursors: m, Index: m}}
	if _, err := New(c); !errors.Is(err, ErrConfig) {
		t.Errorf("best-effort stream without a commit index: %v", err)
	}
}

// The node's client certificate is checked at load for client
// authentication and its validity dates (A3 #89).
func TestClientTLSChecksLeaf(t *testing.T) {
	p := newPKI(t)
	tg := newTarget(t, 2514, nil)
	now := time.Now()
	client := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	for name, c := range map[string]struct {
		usage       []x509.ExtKeyUsage
		from, until time.Time
		ok          bool
	}{
		"valid, clientAuth": {client, now.Add(-time.Hour), now.Add(time.Hour), true},
		"no EKU extension":  {nil, now.Add(-time.Hour), now.Add(time.Hour), true},
		"any EKU":           {[]x509.ExtKeyUsage{x509.ExtKeyUsageAny}, now.Add(-time.Hour), now.Add(time.Hour), true},
		"serverAuth only":   {[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(-time.Hour), now.Add(time.Hour), false},
		"expired":           {client, now.Add(-2 * time.Hour), now.Add(-time.Hour), false},
		"not yet valid":     {client, now.Add(time.Hour), now.Add(2 * time.Hour), false},
	} {
		cert := p.issueAt(t, string(node), nil, c.usage, c.from, c.until)
		_, err := ClientTLS(tg, p.roots, &cert)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v is not ErrConfig", name, err)
		}
	}
	// An EKU extension listing only OIDs Go does not know is still an EKU
	// extension without clientAuth (A3 #94).
	unknown := p.issueAt(t, string(node), nil, nil, now.Add(-time.Hour), now.Add(time.Hour), asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1})
	if leaf, _ := x509.ParseCertificate(unknown.Certificate[0]); len(leaf.ExtKeyUsage) != 0 || len(leaf.UnknownExtKeyUsage) != 1 {
		t.Fatalf("test certificate: known %v, unknown %v", leaf.ExtKeyUsage, leaf.UnknownExtKeyUsage)
	}
	if _, err := ClientTLS(tg, p.roots, &unknown); !errors.Is(err, ErrConfig) {
		t.Errorf("unknown EKU only: %v", err)
	}
}

var _ store.CommitIndex = (*memStore)(nil)

// Status.Open is set while a session is open, even with nothing to send,
// and cleared when the collector goes away, so the node can tell a quiet
// target from a down one.
func TestStatusOpen(t *testing.T) {
	r := newRig(t, nil, nil)
	var f *Forwarder
	opened := false
	r.run(func() bool {
		if f == nil {
			return false
		}
		if !opened && !f.Status().Open.IsZero() {
			opened = true
			r.srv.Close()
		}
		return opened && f.Status().Open.IsZero() && f.Status().LastErr != nil
	}, func(x *Forwarder) { f = x })
	if f.Status().Confirmed != 0 {
		t.Errorf("confirmed %d with nothing committed", f.Status().Confirmed)
	}
}

// refusing is a HealthSink that refuses while refuse is set, as a health
// stream at quota does.
type refusing struct {
	sink
	refuse atomic.Bool
}

func (r *refusing) Emit(ctx context.Context, h event.Health) (store.Key, error) {
	if r.refuse.Load() {
		return store.Key{}, errors.New("quota reached")
	}
	return r.sink.Emit(ctx, h)
}

// A health stream that refuses the forwarder's reports does not stop it:
// the events are still sent, the reports are counted and committed once the
// sink accepts again (A4 review of #98: a full store must still drain), and
// the cursor is saved past them only then (A6 #94).
func TestRefusedReportDoesNotStall(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	hs := &refusing{sink: r.cfg.Health.(sink)}
	hs.refuse.Store(true)
	r.cfg.Health = hs
	r.fill(5)
	var f *Forwarder
	refused := false
	r.run(func() bool {
		if f == nil {
			return false
		}
		st := f.Status()
		if !refused && st.Confirmed >= 5 && st.Unreported == 5 {
			refused = true
			if st.ReportErr == nil {
				t.Error("no ReportErr while refused")
			}
			// Sent and confirmed, but the cursor waits for the reports;
			// Status says how far the target confirmed.
			if c := r.m.cursor(serStream); c != 0 {
				t.Errorf("ser cursor %d saved past an owed report", c)
			}
			if ss := st.Streams[serStream]; ss.Cursor != 0 || ss.Confirmed != 5 {
				t.Errorf("ser status %+v, want cursor 0 and confirmed 5", ss)
			}
			hs.refuse.Store(false)
		}
		return refused && st.Unreported == 0 && r.m.cursor(hlStream) == 5 && r.m.cursor(serStream) == 5
	}, func(x *Forwarder) { f = x })
	if f.Status().ReportErr != nil {
		t.Errorf("ReportErr %v after every report committed", f.Status().ReportErr)
	}
	var named []string
	for _, m := range r.srv.Acked() {
		if s := string(m.Data); strings.Contains(s, `htype="forward.text-omitted"`) {
			named = append(named, s[strings.Index(s, "sel751-feeder1/ser:"):][:20])
		}
	}
	if len(named) != 5 {
		t.Errorf("text-omitted forwarded for %v", named)
	}
}

// Past maxOwed the refused reports are counted per type and summed up in
// one event once the sink accepts.
func TestRefusedReportsSummarised(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	hs := &refusing{sink: r.cfg.Health.(sink)}
	hs.refuse.Store(true)
	r.cfg.Health = hs
	r.fill(5)
	var f *Forwarder
	refused := false
	r.run(func() bool {
		if f == nil {
			return false
		}
		if !refused && f.Status().Confirmed >= 5 && f.Status().Unreported == 5 {
			refused = true
			hs.refuse.Store(false)
		}
		return refused && f.Status().Unreported == 0 && r.m.cursor(hlStream) == 3 && r.m.cursor(serStream) == 5
	}, func(x *Forwarder) { f = x; f.maxOwed = 2 })
	var summary bool
	for _, m := range r.srv.Acked() {
		s := string(m.Data)
		summary = summary || strings.Contains(s, `htype="forward.text-omitted"`) && strings.Contains(s, `unreported=3`)
	}
	if !summary {
		t.Error("no summary for the 3 reports past maxOwed")
	}
}

// A too-large event whose report is refused holds only its own stream; the
// others drain, and it is released once the report is committed and
// confirmed.
func TestTooLargeReportRefused(t *testing.T) {
	other := store.StreamID("platform/other")
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	r.cfg.Streams = append(r.cfg.Streams, Stream{ID: other, Outbox: r.m, Cursors: r.m})
	hs := &refusing{sink: r.cfg.Health.(sink)}
	hs.refuse.Store(true)
	r.cfg.Health = hs
	r.m.commit(t, other, healthEvent(event.HealthSourceSilent, map[string]string{"note": strings.Repeat("x", 1200)}))
	r.m.commit(t, other, healthEvent(event.HealthSourceSilent, map[string]string{"note": "small"}))
	r.m.commit(t, hlStream, healthEvent(event.HealthSourceSilent, map[string]string{"note": "ok"}))
	var f *Forwarder
	refused := false
	r.run(func() bool {
		if f == nil {
			return false
		}
		if !refused && r.m.cursor(hlStream) == 1 && strings.Contains(f.Status().Streams[other].Blocked, "was refused") {
			refused = true
			hs.refuse.Store(false)
		}
		return refused && r.m.cursor(other) == 2
	}, func(x *Forwarder) { f = x })
}

// A6 #94 must: a refused report survives a restart. While it is owed the
// cursor stays before the event it is about, so the next process sends the
// event again and raises the report again.
func TestOwedReportSurvivesRestart(t *testing.T) {
	r := newRig(t, nil, func(tg *syslog.Target) { tg.MaxMessageOctets = 1000 })
	hs := &refusing{sink: r.cfg.Health.(sink)}
	hs.refuse.Store(true)
	r.cfg.Health = hs
	r.fill(5)
	var f *Forwarder
	r.run(func() bool {
		return f != nil && f.Status().Confirmed >= 5 && f.Status().Unreported == 5
	}, func(x *Forwarder) { f = x })
	if c := r.m.cursor(serStream); c != 0 {
		t.Fatalf("ser cursor %d saved past owed reports", c)
	}
	// The process stops with the reports owed; the next one is accepted.
	hs.refuse.Store(false)
	r.run(func() bool { return r.m.cursor(serStream) == 5 && len(r.m.keys(hlStream)) == 5 }, nil)
	if n := r.healthCount(event.HealthForwardTextOmitted); n < 5 {
		t.Errorf("%d forward.text-omitted forwarded after the restart, want 5", n)
	}
}

// The same for a skipped range: the cursor stays before the gap, so the
// next process finds it again and reports it.
func TestOwedGapSurvivesRestart(t *testing.T) {
	r := newRig(t, nil, nil)
	hs := &refusing{sink: r.cfg.Health.(sink)}
	hs.refuse.Store(true)
	r.cfg.Health = hs
	r.fill(30)
	if err := r.m.SaveCursor(t.Context(), store.Cursor{Consumer: "siem-a", Stream: serStream, Through: 10}); err != nil {
		t.Fatal(err)
	}
	r.m.prune(serStream, 20)
	var f *Forwarder
	r.run(func() bool {
		return f != nil && f.Status().Confirmed >= 10 && f.Status().Unreported == 1
	}, func(x *Forwarder) { f = x })
	if c := r.m.cursor(serStream); c != 10 {
		t.Fatalf("ser cursor %d, want 10: saved past an unreported gap", c)
	}
	hs.refuse.Store(false)
	r.run(func() bool { return r.m.cursor(serStream) == 30 && r.m.cursor(hlStream) >= 1 }, nil)
	var found bool
	for _, m := range r.srv.Acked() {
		s := string(m.Data)
		found = found || strings.Contains(s, `htype="forward.unreachable"`) && strings.Contains(s, `first_skipped=11`) && strings.Contains(s, `last_skipped=20`)
	}
	if !found {
		t.Error("no forward.unreachable for 11-20 after the restart")
	}
}

// The health stream of a required target is never held for an owed
// report: its cursor is what frees the stream that refused it.
func TestRequiredHealthStreamNotHeld(t *testing.T) {
	r := newRig(t, nil, nil)
	hs := &refusing{sink: r.cfg.Health.(sink)}
	hs.refuse.Store(true)
	r.cfg.Health = hs
	for range 30 {
		r.m.commit(t, hlStream, healthEvent(event.HealthSourceSilent, nil))
	}
	if err := r.m.SaveCursor(t.Context(), store.Cursor{Consumer: "siem-a", Stream: hlStream, Through: 10}); err != nil {
		t.Fatal(err)
	}
	r.m.prune(hlStream, 20)
	var f *Forwarder
	r.run(func() bool {
		return f != nil && r.m.cursor(hlStream) == 30 && f.Status().Unreported == 1
	}, func(x *Forwarder) { f = x })
}

// A6 #94 should: a new best-effort target saves its window start as its
// cursor before anything is confirmed, so a later process does not move
// the start past events that were inside the window when it began.
func TestBestEffortStartSaved(t *testing.T) {
	var refuse atomic.Bool
	refuse.Store(true)
	srv, err := relptest.Start(nil, func(int, relptest.Message) relptest.Action {
		if refuse.Load() {
			return relptest.Refuse
		}
		return relptest.Ack
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tg := newTarget(t, srv.Addr().Port, func(x *syslog.Target) { plainRELP(x); x.ReplaySeconds = 2 })
	dial, err := DialTCP(tg, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m := newStore()
	e := row8(t)
	for range 10 {
		m.commitAt(t, serStream, e, time.Now().Add(-time.Hour))
	}
	for range 5 {
		m.commit(t, serStream, e)
	}
	r := &rig{t: t, m: m, srv: srv, tg: tg, cfg: Config{
		Target:       tg,
		Streams:      []Stream{{ID: serStream, Outbox: m, Cursors: m, Index: m}, {ID: hlStream, Outbox: m, Cursors: m, Index: m}},
		HealthStream: hlStream, Dial: dial, Health: sink{t: t, m: m},
		ResponseTimeout: 2 * time.Second, Poll: 10 * time.Millisecond, RetryMin: 5 * time.Millisecond,
	}}
	// The collector refuses everything: nothing is confirmed, but the
	// window start is saved.
	r.run(func() bool { return m.cursor(serStream) == 10 && srv.Conns() >= 2 }, nil)
	// The window passes the 5 recent events; a new process still sends
	// them, from the saved start.
	time.Sleep(2500 * time.Millisecond)
	refuse.Store(false)
	r.run(func() bool { return m.cursor(serStream) == 15 }, nil)
}

// bestEffortRig is a lab-only plain relp best-effort target with a one-hour
// window over m, dialled through dial when it is set.
func bestEffortRig(t *testing.T, m *memStore, dial func(context.Context) (net.Conn, error)) *rig {
	t.Helper()
	srv, err := relptest.Start(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	tg := newTarget(t, srv.Addr().Port, plainRELP)
	tcp, err := DialTCP(tg, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if dial == nil {
		dial = tcp
	}
	return &rig{t: t, m: m, srv: srv, tg: tg, cfg: Config{
		Target:       tg,
		Streams:      []Stream{{ID: serStream, Outbox: m, Cursors: m, Index: m}, {ID: hlStream, Outbox: m, Cursors: m, Index: m}},
		HealthStream: hlStream, Dial: func(ctx context.Context) (net.Conn, error) { return dial(ctx) }, Health: sink{t: t, m: m},
		ResponseTimeout: 2 * time.Second, Poll: 10 * time.Millisecond, RetryMin: 5 * time.Millisecond, RetryMax: 20 * time.Millisecond,
	}}
}

// The window start is saved even while the collector cannot be reached
// (A6 #94).
func TestBestEffortStartSavedWhileDown(t *testing.T) {
	m := newStore()
	e := row8(t)
	for range 10 {
		m.commitAt(t, serStream, e, time.Now().Add(-2*time.Hour))
	}
	for range 5 {
		m.commit(t, serStream, e)
	}
	var dials atomic.Int32
	r := bestEffortRig(t, m, func(context.Context) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("collector down")
	})
	r.run(func() bool { return m.cursor(serStream) == 10 && dials.Load() >= 2 }, nil)
}

// With nothing committed before the window, the start is the first
// retained event, so a jump past it later is reported, even from seq 0
// (A6 #94).
func TestBestEffortGapFromZero(t *testing.T) {
	m := newStore()
	for range 5 {
		m.commit(t, serStream, row8(t))
	}
	var down atomic.Bool
	down.Store(true)
	var dials atomic.Int32
	var r *rig
	r = bestEffortRig(t, m, func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		if down.Load() {
			return nil, errors.New("collector down")
		}
		d, _ := DialTCP(r.tg, time.Second)
		return d(ctx)
	})
	r.run(func() bool {
		if down.Load() && dials.Load() >= 2 {
			// The start (0) was worked out before the first dial; 1-2 are
			// then pruned before the target reads them.
			m.prune(serStream, 2)
			down.Store(false)
		}
		return !down.Load() && m.cursor(serStream) == 5 && m.cursor(hlStream) >= 1
	}, nil)
	var found bool
	for _, msg := range r.srv.Acked() {
		s := string(msg.Data)
		found = found || strings.Contains(s, `htype="forward.unreachable"`) && strings.Contains(s, `first_skipped=1`) && strings.Contains(s, `last_skipped=2`)
	}
	if !found {
		t.Error("no forward.unreachable for 1-2")
	}
}

// Events pruned before a new best-effort target existed are not its loss:
// it starts at the first retained event and reports nothing.
func TestBestEffortNoFalseGap(t *testing.T) {
	m := newStore()
	e := row8(t)
	for range 5 {
		m.commitAt(t, serStream, e, time.Now().Add(-2*time.Hour))
	}
	for range 5 {
		m.commit(t, serStream, e)
	}
	m.prune(serStream, 5)
	r := bestEffortRig(t, m, nil)
	r.run(func() bool { return m.cursor(serStream) == 10 }, nil)
	if n := r.healthCount(event.HealthForwardUnreachable); n != 0 {
		t.Errorf("%d forward.unreachable for events pruned before the target existed", n)
	}
	if ids := eids(t, r.srv.Acked()); len(ids) != 5 {
		t.Errorf("sent %v, want 6-10", ids)
	}
}
