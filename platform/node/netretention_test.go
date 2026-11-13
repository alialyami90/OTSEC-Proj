package node

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/netretain"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// The retention consumer in the runtime, on the test's wall and monotonic
// clocks: Start creates it and records created; a Tick past the retention
// moves it, the move's record stamped 0.12 in a chain that otherwise holds
// 0.11 records, and the passed alerts become prunable; a
// restart resumes from the record; status shows both cutoffs. Desk only.
// retentionRig is a node with a 30-day alert retention and no forwarding
// target, on the test's wall and monotonic clocks.
type retentionRig struct {
	t    *testing.T
	c    *Config
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

func newRetentionRig(t *testing.T) *retentionRig {
	c, _ := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection() // 30 days, no target
	})
	return &retentionRig{t: t, c: c, wall: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), mono: time.Minute}
}

func (g *retentionRig) now() time.Time { g.mu.Lock(); defer g.mu.Unlock(); return g.wall }

func (g *retentionRig) monoNow() time.Duration { g.mu.Lock(); defer g.mu.Unlock(); return g.mono }

func (g *retentionRig) advance(d time.Duration) {
	g.mu.Lock()
	g.wall, g.mono = g.wall.Add(d), g.mono+d
	g.mu.Unlock()
}

// start starts the node, its monotonic clock restarting.
func (g *retentionRig) start() (*Runtime, *Status) {
	g.t.Helper()
	g.mu.Lock()
	g.mono = time.Minute
	g.mu.Unlock()
	st := NewStatus("", nil, g.now)
	r, err := Start(bg, g.c, RuntimeOptions{Status: st, Now: g.now, Mono: g.monoNow, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		g.t.Fatal(err)
	}
	waitSensor(g.t, r)
	return r, st
}

// alert commits one alert now.
func (g *retentionRig) alert(r *Runtime) {
	g.t.Helper()
	stream := NetAlertStream(sensorID)
	ev := []byte(`{"schema":"otsec.event/0.1","id":{"node_id":"site-a-node1","stream":"` + string(stream) + `","seq":0},` +
		`"origin":"platform","kind":"telemetry-health","source":{"origin_auth":"platform"},` +
		`"received":{"utc":"2026-11-01T00:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},` +
		`"health":{"type":"store.test","details":{}}}`)
	if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassNetworkAlert, Event: ev}); err != nil {
		g.t.Fatal(err)
	}
}

// moves are the node's store.retention_moved records, the chain verified.
func (g *retentionRig) moves(r *Runtime) (out []*audit.Record) {
	g.t.Helper()
	for _, rec := range auditRecords(g.t, r) {
		if rec.Action == audit.ActionStoreRetentionMoved {
			out = append(out, rec)
		}
	}
	return out
}

// alarms counts status's alarms of code.
func alarms(st *Status, code string) (n int) {
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == code {
			n++
		}
	}
	return n
}

// The retention consumer in the runtime, on the test's wall and monotonic
// clocks: Start creates it and records created; a Tick past the retention
// moves it, the move's record stamped 0.12 in a chain that otherwise holds
// 0.11 records, and the passed alerts become prunable; a
// restart resumes from the record; status shows both cutoffs. Desk only.
func TestNetRetentionRuntime(t *testing.T) {
	g := newRetentionRig(t)
	c := g.c
	now, advance, moves := g.now, g.advance, g.moves
	r, st := g.start()
	stream := NetAlertStream(sensorID)
	alert := func() { t.Helper(); g.alert(r) }
	m := moves(r)
	if len(m) != 1 || m[0].Retention.Bound != audit.BoundCreated || m[0].Contract != RetentionContract ||
		m[0].Actor.ID != "site-a-node1" || m[0].Target.SensorID != sensorID {
		t.Fatalf("at start: %+v", m)
	}
	if s := st.Snapshot("x").NetRetention; s == nil || !s.Running || s.Stream != string(stream) {
		t.Fatalf("status %+v", s)
	}

	alert()
	alert()
	advance(time.Hour)
	alert()
	advance(30*24*time.Hour - time.Hour + time.Minute) // the first two are past the retention
	r.Tick(bg)
	m = moves(r)
	if len(m) != 2 || m[1].Retention.Bound != audit.BoundWall || m[1].Retention.FromSeq != 0 || m[1].Retention.ToSeq != 2 {
		t.Fatalf("after the retention: %+v", m[len(m)-1].Retention)
	}
	// The passed alerts are prunable: the boundary over the node's
	// consumers is the move's to_seq. (Prune removes them once the class
	// is over its target, as for every class.)
	consumers, err := c.Consumers()
	if err != nil {
		t.Fatal(err)
	}
	db := r.Store(stream)
	if b, err := c5.ComputeBoundary(bg, db, db, consumers, stream, c5.ClassNetworkAlert, now()); err != nil || b.Through() != 2 {
		t.Fatalf("boundary %v, %v; want through 2", b, err)
	}
	// The chain mixes minors: every other node record keeps the 0.11
	// stamp, and the chain verifies (auditRecords runs VerifyChain).
	all := auditRecords(t, r)
	var older int
	for _, rec := range all {
		if rec.Contract == audit.ContractID {
			older++
		}
	}
	if older == 0 || audit.ContractID == RetentionContract {
		t.Fatalf("no %s record beside the %s ones", audit.ContractID, RetentionContract)
	}
	if err := audit.VerifyConfigFrom(all, 1); err != nil {
		t.Fatal(err)
	}
	// The same move stamped with the node's other minor is refused (D1 in
	// D4-70).
	old := *m[1]
	old.Contract = audit.ContractID
	if err := old.Validate(); err == nil {
		t.Fatalf("store.retention_moved stamped %s accepted", audit.ContractID)
	}
	s := st.Snapshot("x").NetRetention
	if s.Cursor != 2 || !s.CursorSaved || s.Cutoff.IsZero() || !s.WallCutoff.Equal(now().Add(-30*24*time.Hour)) {
		t.Fatalf("status %+v", s)
	}
	r.Close()

	// A restart resumes from the record: no new created record, and the
	// first move after it is bounded by the start allowance.
	r, _ = g.start()
	defer r.Close()
	advance(2 * time.Hour)
	r.Tick(bg)
	m = moves(r)
	if len(m) != 3 || m[2].Retention.Bound != audit.BoundWall || m[2].Retention.FromSeq != 2 || m[2].Retention.ToSeq != 3 {
		t.Fatalf("after a restart: %+v", m[len(m)-1].Retention)
	}
}

// With a forwarding target there is no retention consumer: nothing is
// recorded and status has no section.
func TestNetRetentionOffWithTarget(t *testing.T) {
	c, _ := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
		delete(nc.NetworkSensor, "alert_retention_days")
		nc.AddRELPTarget("central", "127.0.0.1", 6514, "test-ca", "test-client", "test/durable-ack", true)
	})
	st := NewStatus("", nil, nil)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	waitSensor(t, r)
	r.Tick(bg)
	for _, rec := range auditRecords(t, r) {
		if rec.Action == audit.ActionStoreRetentionMoved {
			t.Fatalf("a retention record with a target: %+v", rec)
		}
	}
	if st.Snapshot("x").NetRetention != nil {
		t.Fatal("a retention status with a target")
	}
}

// A record that fails stalls the consumer: it retries at each tick, the
// alarm is raised once across them, and status shows the error. A record
// that commits but reports an error (C5's Append on a cancelled context)
// leaves the chain whole, because the consumer reads the record back. The first step that succeeds clears the
// error, and a later stall raises the alarm again (D6's R1 and R2 on #559).
func TestNetRetentionStall(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	g.alert(r)
	g.alert(r)
	g.advance(30*24*time.Hour + time.Hour)

	r.retentionRecord = func(context.Context, audit.Retention) error { return errors.New("audit refused") }
	for range 3 {
		r.Tick(bg)
		g.advance(time.Minute)
	}
	if n := alarms(st, AlarmNetRetentionStalled); n != 1 {
		t.Fatalf("stalled raised %d times, want once", n)
	}
	if s := st.Snapshot("x").NetRetention; !s.Running || !strings.Contains(s.Error, "audit refused") {
		t.Fatalf("status while stalled %+v", s)
	}

	// Committed, and reported as failed.
	r.retentionRecord = func(ctx context.Context, m audit.Retention) error {
		if err := r.recordRetention(ctx, m); err != nil {
			return err
		}
		return context.Canceled
	}
	r.Tick(bg)
	if m := g.moves(r); len(m) != 2 || m[1].Retention.ToSeq != 2 {
		t.Fatalf("the committed move: %+v", m[len(m)-1].Retention)
	}
	r.retentionRecord = nil
	g.advance(time.Minute)
	r.Tick(bg)
	if s := st.Snapshot("x").NetRetention; !s.Running || s.Error != "" || s.Cursor != 2 {
		t.Fatalf("status after the stall %+v", s)
	}
	g.alert(r)
	g.advance(30*24*time.Hour + time.Hour)
	r.Tick(bg)
	m := g.moves(r)
	if last := m[len(m)-1].Retention; len(m) != 3 || last.FromSeq != 2 || last.ToSeq != 3 {
		t.Fatalf("the move after the re-sync: %+v", last)
	}
	if err := audit.VerifyConfigFrom(auditRecords(t, r), 1); err != nil {
		t.Fatal(err)
	}
	if n := alarms(st, AlarmNetRetentionStalled); n != 1 {
		t.Fatalf("stalled raised %d times before a new stall", n)
	}
	g.alert(r)
	g.advance(30*24*time.Hour + time.Hour)
	r.retentionRecord = func(context.Context, audit.Retention) error { return errors.New("audit refused") }
	r.Tick(bg)
	if n := alarms(st, AlarmNetRetentionStalled); n != 2 {
		t.Fatalf("a new stall raised %d alarms in all, want 2", n)
	}
}

// The lag behind the wall-clock cutoff, after 31 days down with a 30-day
// retention: over the retention, status shows it and the alarm is raised
// once; at exactly the retention it is cleared. Then the store's cursor is
// moved past the latest record with no record, and the next start shows
// and alarms it (D3's R1 and S1 on #559).
func TestNetRetentionLagAndUnrecorded(t *testing.T) {
	g := newRetentionRig(t)
	r, _ := g.start()
	r.Close()
	g.advance(31 * 24 * time.Hour) // down
	r, st := g.start()
	const R = 30 * 24 * time.Hour
	lag := func() *NetRetentionStatus { return st.Snapshot("x").NetRetention }
	// Started: the bound is the persisted cutoff plus an hour.
	if s := lag(); !s.Lagging || s.LagS != int64((31*24*time.Hour-time.Hour)/time.Second) || alarms(st, AlarmNetRetentionLagging) != 1 {
		t.Fatalf("after the downtime: %+v", s)
	}
	// The bound gains an hour an hour on the wall cutoff.
	g.advance(22 * time.Hour)
	r.Tick(bg)
	if s := lag(); !s.Lagging || s.LagS != int64((R+time.Hour)/time.Second) || alarms(st, AlarmNetRetentionLagging) != 1 || alarms(st, AlarmNetRetentionLagCleared) != 0 {
		t.Fatalf("an hour over the retention: %+v", s)
	}
	g.advance(time.Hour)
	r.Tick(bg)
	if s := lag(); s.Lagging || s.LagS != int64(R/time.Second) || alarms(st, AlarmNetRetentionLagCleared) != 1 {
		t.Fatalf("at the retention: %+v", s)
	}

	// The store's cursor moved with no record.
	g.alert(r)
	g.alert(r)
	stream := NetAlertStream(sensorID)
	if err := r.Store(stream).SaveCursor(bg, c5.Cursor{Consumer: netretain.ConsumerID, Stream: stream, Through: 2}); err != nil {
		t.Fatal(err)
	}
	r.Close()
	r, st = g.start()
	defer r.Close()
	m := g.moves(r)
	if last := m[len(m)-1].Retention; last.Bound != audit.BoundCreated || last.FromSeq != 2 || last.ToSeq != 2 {
		t.Fatalf("after the unrecorded jump: %+v", last)
	}
	if s := st.Snapshot("x").NetRetention; s.UnrecordedTo == nil || *s.UnrecordedTo != 0 || s.Cursor != 2 || alarms(st, AlarmNetRetentionUnrecorded) != 1 {
		t.Fatalf("status %+v", s)
	}
}

// An idle stream whose alerts have all been passed is not lagging: its
// bound is held at the wall cutoff, so 60 idle days show no lag and raise
// no lag alarm (D1 in D4-71).
func TestNetRetentionIdleNoLag(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	g.alert(r)
	g.advance(30*24*time.Hour + time.Hour)
	r.Tick(bg)
	if m := g.moves(r); len(m) != 2 || m[1].Retention.ToSeq != 1 {
		t.Fatalf("the alert not passed: %+v", m[len(m)-1].Retention)
	}
	for range 60 {
		g.advance(24 * time.Hour)
		r.Tick(bg)
		if s := st.Snapshot("x").NetRetention; s.LagS != 0 || s.Lagging {
			t.Fatalf("an idle stream lags: %+v", s)
		}
	}
	if n := alarms(st, AlarmNetRetentionLagging); n != 0 {
		t.Fatalf("lagging raised %d times on an idle stream", n)
	}
}

// setWall sets the wall clock alone, as a clock step does.
func (g *retentionRig) setWall(w time.Time) { g.mu.Lock(); g.wall = w; g.mu.Unlock() }

// commitAt commits one health event on stream through the runtime's Log and
// returns its commit time as the store read it back.
func (g *retentionRig) commitAt(r *Runtime, stream c5.StreamID, class c5.StreamClass) time.Time {
	g.t.Helper()
	ev := []byte(`{"schema":"otsec.event/0.1","id":{"node_id":"site-a-node1","stream":"` + string(stream) + `","seq":0},` +
		`"origin":"platform","kind":"telemetry-health","source":{"origin_auth":"platform"},` +
		`"received":{"utc":"2026-11-01T00:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},` +
		`"health":{"type":"store.test","details":{}}}`)
	if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: class, Event: ev}); err != nil {
		g.t.Fatal(err)
	}
	got, err := r.Store(stream).Read(bg, stream, 0, 1000)
	if err != nil || len(got) == 0 {
		g.t.Fatalf("read back %s: %v, %d events", stream, err, len(got))
	}
	return got[len(got)-1].CommittedAt
}

// D6's P1 on #559 (D4-71): through the runtime, only the network database
// floors commit times at its wall mark. With the clock stepped forward and
// then back, a commit on a network stream not written before takes the
// forward time, and a commit on an evidence stream not written before takes
// the stepped-back time. A runtime that set WallMark on every database, or
// on none, fails here. Desk only.
func TestNetWallMarkNetworkDBOnly(t *testing.T) {
	g := newRetentionRig(t)
	r, _ := g.start()
	defer r.Close()
	t0 := g.now()
	forward, back := t0.Add(10*24*time.Hour), t0.Add(time.Hour)
	g.setWall(forward)
	g.commitAt(r, NetAlertStream(sensorID), c5.ClassNetworkAlert)
	g.commitAt(r, SERStream(relayID), c5.ClassAdapterEvidence)
	g.setWall(back)
	if at := g.commitAt(r, NetObservationStream(sensorID), c5.ClassNetworkObservation); !at.Equal(forward) {
		t.Errorf("network database: a commit after the step back at %s, want the mark %s", at, forward)
	}
	if at := g.commitAt(r, QuarantineStream(relayID), c5.ClassAdapterEvidence); !at.Equal(back) {
		t.Errorf("evidence database: a commit after the step back at %s, want the clock's %s", at, back)
	}
}

// AP-36's V1 at its edge (D6, D4-71): a lag of exactly the retention raises
// no alarm, and one second more raises it once. Over the next two days of
// hourly ticks the lag falls, the alarm is cleared once if it was raised,
// and neither is raised again. Desk only.
func TestNetRetentionLagEdge(t *testing.T) {
	const R = 30 * 24 * time.Hour
	for _, c := range []struct {
		over    time.Duration
		lagging int
	}{{0, 0}, {time.Second, 1}} {
		g := newRetentionRig(t)
		r, _ := g.start()
		r.Close()
		g.advance(R + time.Hour + c.over) // down, with the start's hour: at start the lag is R + over
		r, st := g.start()
		s := st.Snapshot("x").NetRetention
		if s.LagS != int64((R+c.over)/time.Second) || s.Lagging != (c.lagging == 1) || alarms(st, AlarmNetRetentionLagging) != c.lagging {
			t.Fatalf("lag R + %s at start: %+v, %d alarms", c.over, s, alarms(st, AlarmNetRetentionLagging))
		}
		for range 48 {
			g.advance(time.Hour)
			r.Tick(bg)
		}
		if s := st.Snapshot("x").NetRetention; s.Lagging || alarms(st, AlarmNetRetentionLagging) != c.lagging || alarms(st, AlarmNetRetentionLagCleared) != c.lagging {
			t.Fatalf("lag R + %s, two days on: %+v, raised %d, cleared %d", c.over, s,
				alarms(st, AlarmNetRetentionLagging), alarms(st, AlarmNetRetentionLagCleared))
		}
		r.Close()
	}
}

// AP-36's V1 (D6, D4-71), through the runtime: after a downtime D longer
// than the retention, or a cut of the retention from 30 days to 7, status
// shows the lag at start and the alarm is raised once. The first move is
// bounded start, one hour past the persisted cutoff. After k of monotonic
// time the lag is the start's less k, so within an hour of D − k. The alarm
// is cleared once the lag is at most the retention and not raised again,
// and once the lag has closed every move is bounded wall. Desk only.
func TestNetRetentionLagCloses(t *testing.T) {
	const day = 24 * time.Hour
	for _, c := range []struct {
		name string
		down time.Duration
		days int
	}{{"downtime", 35 * day, 30}, {"cut to 7 days", 0, 7}} {
		t.Run(c.name, func(t *testing.T) {
			g := newRetentionRig(t)
			r, _ := g.start()
			for range 48 { // an alert an hour for two days
				g.alert(r)
				g.advance(time.Hour)
			}
			g.advance(30*day - 24*time.Hour) // the first day's alerts are past the retention
			r.Tick(bg)
			before := g.moves(r)
			persisted, _ := time.Parse(time.RFC3339Nano, before[len(before)-1].Retention.CutoffUTC)
			r.Close()

			g.advance(c.down)
			g.c.NetworkSensor.AlertRetentionDays = c.days
			r, st := g.start()
			defer r.Close()
			R := time.Duration(c.days) * day
			lag0 := g.now().Add(-R).Sub(persisted.Add(time.Hour)) // the start's hour, by value (D3's conditions in D4-71)
			if s := st.Snapshot("x").NetRetention; s.LagS != int64(lag0/time.Second) || !s.Lagging || alarms(st, AlarmNetRetentionLagging) != 1 {
				t.Fatalf("at start: %+v, want lag %s", s, lag0)
			}
			m := g.moves(r)[len(before):]
			if len(m) != 1 || m[0].Retention.Bound != audit.BoundStart || m[0].Retention.CutoffUTC != persisted.Add(time.Hour).Format(time.RFC3339Nano) {
				t.Fatalf("the start's move: %d moves, %+v", len(m), m[0].Retention)
			}

			walls := 0
			for k := time.Duration(0); k <= lag0+2*day; {
				g.alert(r)
				g.advance(6 * time.Hour)
				k += 6 * time.Hour
				r.Tick(bg)
				s := st.Snapshot("x").NetRetention
				if want := max(lag0-k, 0); s.LagS != int64(want/time.Second) {
					t.Fatalf("after %s: lag %ds, want %s", k, s.LagS, want)
				}
				cleared := 0
				if lag0-k <= R {
					cleared = 1
				}
				if s.Lagging != (cleared == 0) || alarms(st, AlarmNetRetentionLagging) != 1 || alarms(st, AlarmNetRetentionLagCleared) != cleared {
					t.Fatalf("after %s: %+v, raised %d, cleared %d", k, s, alarms(st, AlarmNetRetentionLagging), alarms(st, AlarmNetRetentionLagCleared))
				}
				all := g.moves(r)
				if last := all[len(all)-1].Retention; s.LagS == 0 && len(all) > len(before)+len(m) && last.WallUTC == g.now().Format(time.RFC3339Nano) {
					if last.Bound != audit.BoundWall {
						t.Fatalf("after %s, with no lag: %+v", k, last)
					}
					walls++
				}
			}
			if walls == 0 {
				t.Fatal("no move once the lag closed")
			}
		})
	}
}

// AP-36's V4 (D6, D4-71), through the runtime with a restart: the alert
// stream and the network database idle past the retention, the node down,
// and the clock set back by more than the retention when it starts. An
// alert committed then, with the node restarted before the clock is
// restored, survives at least half its retention less an hour for each
// start in between, by monotonic time: the wall mark, kept in the
// database, floors its commit time across the restart. Twice: with the
// mark last raised by the move that passed the stream's alerts (its
// evaluation and cursor save), and by a later commit on the observation
// stream. Desk only.
func TestNetRetentionBackwardStepRestart(t *testing.T) {
	const R = 30 * 24 * time.Hour
	for _, c := range []struct {
		name string
		obs  bool
	}{{"mark from the move", false}, {"mark from a commit", true}} {
		t.Run(c.name, func(t *testing.T) {
			g := newRetentionRig(t)
			r, st := g.start()
			g.alert(r) // seq 1
			g.advance(R + 24*time.Hour)
			r.Tick(bg) // passes seq 1
			mark := g.now()
			if s := st.Snapshot("x").NetRetention; s.Cursor != 1 {
				t.Fatalf("seq 1 not passed: %+v", s)
			}
			if c.obs {
				g.advance(time.Hour)
				mark = g.now()
				g.commitAt(r, NetObservationStream(sensorID), c5.ClassNetworkObservation)
			}
			r.Close()

			g.advance(2 * R) // down, idle
			restored := g.now()
			g.setWall(restored.Add(-3 * R)) // and the clock set back
			r, _ = g.start()
			if at := g.commitAt(r, NetAlertStream(sensorID), c5.ClassNetworkAlert); !at.Equal(mark) { // seq 2
				t.Fatalf("seq 2 committed at %s, want the mark %s", at, mark)
			}
			r.Close()

			g.setWall(restored) // restored, and started again
			r, st = g.start()
			defer r.Close()
			// Between the commit and the pass, only the start that restored
			// the clock counts: the one before held the bound at the recorded
			// cutoff, the wall cutoff being behind it (D6 on #563).
			starts := time.Duration(1)
			bound := R/2 - starts*time.Hour
			since := time.Duration(0)
			step := func(d time.Duration) {
				t.Helper()
				g.advance(d)
				r.Tick(bg)
				since += d
				if s := st.Snapshot("x").NetRetention; since <= bound && s.Cursor >= 2 {
					t.Fatalf("seq 2 passed %s after its commit (monotonic), within %s: %+v", since, bound, s)
				}
			}
			for since+6*time.Hour <= bound {
				step(6 * time.Hour)
			}
			for since < R/2+time.Hour { // hourly near the bound, and past it
				step(time.Hour)
			}
			if s := st.Snapshot("x").NetRetention; s.Cursor != 2 {
				t.Fatalf("seq 2 not passed %s after its commit: %+v", since, s)
			}
		})
	}
}
