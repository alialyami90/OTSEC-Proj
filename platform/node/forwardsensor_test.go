package node

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/forward"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// plainTarget is a lab-only, best-effort plain RELP target at port. It
// needs no TLS files, so a run on a PC that cannot lock tls_dir (lockTLS)
// still builds its forwarder.
func plainTarget(name string, port int) map[string]any {
	return map[string]any{
		"schema": "otsec.syslog/0.2", "name": name, "host": "127.0.0.1", "port": port,
		"transport": "relp", "format": "rfc5424", "framing": "relp", "class": "best-effort",
		"max_message_octets": 8192, "facility": 16, "relp_window": 64, "replay_seconds": 3600,
		"acknowledgement": map[string]any{"by": "admin:lab-admin", "at": "2026-10-24T09:00:00Z",
			"reason": "Loopback test collector only (ADR-0005)", "scope": "lab-only"},
	}
}

// sensorForwardConfig is a node with the scheduler's relay, a sensor
// section when sensor is set, and a plain RELP target at each port.
func sensorForwardConfig(t *testing.T, sensor bool, ports ...int) (*Config, string) {
	t.Helper()
	return schedConfig(t, func(nc *nodeconfigtest.Config) {
		if sensor {
			sensorQuotas(nc)
			// A forwarding target confirms the alert stream, so the section
			// carries no alert_retention_days.
			nc.NetworkSensor = sensorSection()
			delete(nc.NetworkSensor, "alert_retention_days")
		}
		for i, p := range ports {
			nc.Targets = append(nc.Targets, plainTarget("lab-"+string(rune('a'+i)), p))
		}
	})
}

// F10 (D5-sensor-node.md section 1.9 item 1; D1's ruling on #662): every
// target's consumer streams are split into its main session and its sensor
// session. The two sets are disjoint, and together they are the target's
// consumer set. The sensor session holds exactly the streams in the sensor
// store set, and the main session the health stream. A node without the
// network_sensor section gets no second session. What each session carries
// is read from its forwarder. Controls: a stream sent to both sessions,
// every stream to the main session, and D6's two mutants: the main
// forwarder also carrying the alert stream, and the sensor forwarder also
// carrying SER.
func TestForwardSessionsSplit(t *testing.T) {
	for _, sensor := range []bool{true, false} {
		c, dir := sensorForwardConfig(t, sensor, 9, 10)
		r, _, _ := start(t, c, dir)
		fw, err := NewForwarding(r)
		if err != nil {
			r.Close()
			t.Fatal(err)
		}
		consumers, err := c.Consumers()
		if err != nil {
			t.Fatal(err)
		}
		if len(fw.targets) != 2 {
			t.Fatalf("sensor %v: %d targets", sensor, len(fw.targets))
		}
		for _, tg := range fw.targets {
			var want []c5.StreamID
			for _, cs := range consumers {
				if string(cs.ID) == tg.t.Name {
					want = append(want, cs.Stream)
				}
			}
			// What each forwarder carries, read from the forwarder itself
			// (D6's B1 on #663), and the lists Check reads it by.
			main := slices.Sorted(maps.Keys(tg.f.Status().Streams))
			var sens []c5.StreamID
			if tg.sf != nil {
				sens = slices.Sorted(maps.Keys(tg.sf.Status().Streams))
			}
			if !slices.Equal(main, tg.streams) || !slices.Equal(sens, tg.sstreams) {
				t.Errorf("sensor %v, target %s: the forwarders carry %v and %v, Check reads %v and %v", sensor, tg.t.Name, main, sens, tg.streams, tg.sstreams)
			}
			for _, id := range sens {
				if slices.Contains(main, id) {
					t.Errorf("sensor %v, target %s: %s is in both sessions", sensor, tg.t.Name, id)
				}
				if d := r.dbFor(id); d == nil || !d.sensor {
					t.Errorf("sensor %v, target %s: the sensor session carries %s, which is not in the sensor store set", sensor, tg.t.Name, id)
				}
			}
			for _, id := range main {
				if d := r.dbFor(id); d != nil && d.sensor {
					t.Errorf("sensor %v, target %s: the main session carries %s, which is in the sensor store set", sensor, tg.t.Name, id)
				}
			}
			got := slices.Concat(main, sens)
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("sensor %v, target %s: the sessions carry %v, the consumer set is %v", sensor, tg.t.Name, got, want)
			}
			if !slices.Contains(main, HealthStream) {
				t.Errorf("sensor %v, target %s: the main session does not carry %s", sensor, tg.t.Name, HealthStream)
			}
			switch {
			case sensor && (tg.sf == nil || !slices.Contains(sens, NetAlertStream(sensorID))):
				t.Errorf("target %s: no sensor session carrying %s (%v)", tg.t.Name, NetAlertStream(sensorID), sens)
			case !sensor && (tg.sf != nil || len(tg.sstreams) != 0):
				t.Errorf("target %s: a sensor session without the network_sensor section (%v)", tg.t.Name, tg.sstreams)
			}
		}
		r.Close()
	}
}

// F5's forwarded-SER leg (D1's ruling 6852845352; D6's conditions on #663):
// while the network database is not open, or is swapped out while its
// Resume is held, a scheduled run's SER events reach the target and are
// confirmed, and the sensor session's attempts fail on the unreadable
// stream. Control: one session for every stream, as on main, whose
// attempts all fail, so nothing is confirmed.
func TestSensorStoreNotOpenForwardingGoesOn(t *testing.T) {
	neverOpen := SensorSeams{Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
		rep := c5.RunStartup(ctx, env, p)
		if db, ok := store.AsDB(rep.Store); ok {
			db.Close()
		}
		return rep
	}}
	for _, leg := range []string{"not-open", "resume-held"} {
		t.Run(leg, func(t *testing.T) {
			srv, err := relptest.Start(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			c, dir := sensorForwardConfig(t, true, srv.Addr().Port)
			seams := neverOpen
			if leg == "resume-held" {
				var in chan struct{}
				var release func()
				seams, in, release = heldResume()
				r, _ := startSeams(t, c, dir, seams)
				t.Cleanup(func() { r.Close() })
				t.Cleanup(release)
				go r.Tick(bg)
				select {
				case <-in:
				case <-time.After(10 * time.Second):
					t.Fatal("the network database's Resume was not reached")
				}
				forwardsSER(t, r)
				return
			}
			r, _ := startSeams(t, c, dir, seams)
			defer r.Close()
			if r.Store(NetAlertStream(sensorID)) != nil {
				t.Fatal("the network database is open")
			}
			forwardsSER(t, r)
		})
	}
}

// forwardsSER stores a scheduled run's SER rows, runs the node's
// forwarding, and waits until the target has confirmed every SER event and
// the sensor session has failed an attempt on its stream.
func forwardsSER(t *testing.T, r *Runtime) {
	t.Helper()
	runSent(t, r)
	ser := SERStream(relayID)
	last, err := r.Store(ser).LastCommitted(bg, ser)
	if err != nil || last == 0 {
		t.Fatalf("SER stream: last %d, %v", last, err)
	}
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); fw.Run(ctx) }()
	defer func() { cancel(); wg.Wait() }()
	tg := fw.targets[0]
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		confirmed := tg.f.Status().Streams[ser].Confirmed >= last
		sensorFailed := tg.sf != nil && tg.sf.Status().LastErr != nil
		if confirmed && sensorFailed {
			break
		}
		if time.Now().After(deadline) {
			var serr error
			if tg.sf != nil {
				serr = tg.sf.Status().LastErr
			}
			t.Fatalf("after 15 s: SER confirmed %v (of %d), sensor session's last error %v; main session %+v", confirmed, last, serr, tg.f.Status())
		}
	}
	if err := tg.sf.Status().LastErr; !strings.Contains(err.Error(), "not open") {
		t.Fatalf("the sensor session's attempt failed on %v, not on its database not open", err)
	}
}

// D6's N2 on #662: Check judges the sensor session's reachability on its
// own status. With the main session open and caught up, a sensor session
// that has had no session open for UnreachableAfter raises one
// forward-unreachable whose detail names the sensor session and its
// streams, and one forward.unreachable health event with session "sensor";
// the main session raises nothing. Then the main session closes too, and
// its own alarm names no sensor session. Controls: Check ignoring the
// sensor session's status, and the sensor session's alarm not named.
func TestSensorSessionUnreachableNamed(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 10, 25, 6, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	c, _ := sensorForwardConfig(t, true, 9) // the forwarders are never run
	st := NewStatus("", nil, clock)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Now: clock, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	waitSensor(t, r)
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	tg := fw.targets[0]
	// forward-unreachable is judged for required targets only, which need
	// relp-tls and locked TLS files (lockTLS); the judgment reads only the
	// class, so this plain target is taken as required.
	req := *tg.t
	req.Class = syslog.ClassRequired
	tg.t = &req
	caughtUp := func(open time.Time, ids []c5.StreamID) forward.Status {
		fs := forward.Status{Open: open, Streams: map[c5.StreamID]forward.StreamStatus{}}
		for _, id := range ids {
			if db := r.Store(id); db != nil {
				last, _ := db.LastCommitted(bg, id)
				fs.Streams[id] = forward.StreamStatus{Cursor: last, Confirmed: last}
			}
		}
		return fs
	}
	unreachable := func() (out []StatusAlarm) {
		for _, a := range st.Snapshot("site-a-node1").Alarms {
			if a.Code == AlarmForwardUnreachable && a.Target == tg.t.Name {
				out = append(out, a)
			}
		}
		return out
	}
	sensorDown := caughtUp(time.Time{}, tg.sstreams)
	sensorDown.LastErr = errNotOpenForTest
	fw.checkSessions(bg, tg, caughtUp(clock(), tg.streams), &sensorDown)
	advance(UnreachableAfter + time.Second)
	fw.checkSessions(bg, tg, caughtUp(clock(), tg.streams), &sensorDown)
	fw.checkSessions(bg, tg, caughtUp(clock(), tg.streams), &sensorDown)
	got := unreachable()
	if len(got) != 1 {
		t.Fatalf("%d forward-unreachable alarms with the sensor session down and the main session open: %+v", len(got), got)
	}
	streams := string(NetAlertStream(sensorID))
	if d := got[0].Detail; !strings.HasPrefix(d, SensorSessionPrefix) || !strings.Contains(d, streams) {
		t.Fatalf("the sensor session's alarm does not name it and its streams: %q", d)
	}
	ev := forwardUnreachableEvents(t, r)
	if len(ev) != 1 || ev[0]["session"] != "sensor" || ev[0]["streams"] != streams || ev[0]["target"] != tg.t.Name {
		t.Fatalf("forward.unreachable events %v", ev)
	}

	// The main session closes: its alarm names no sensor session.
	fw.checkSessions(bg, tg, caughtUp(time.Time{}, tg.streams), &sensorDown)
	advance(UnreachableAfter + time.Second)
	fw.checkSessions(bg, tg, caughtUp(time.Time{}, tg.streams), &sensorDown)
	got = unreachable()
	if len(got) != 2 || strings.Contains(got[1].Detail, SensorSessionPrefix) {
		t.Fatalf("after the main session closed: %+v", got)
	}
	ev = forwardUnreachableEvents(t, r)
	if len(ev) != 2 || ev[1]["session"] != "" {
		t.Fatalf("forward.unreachable events after the main session closed: %v", ev)
	}
}

// F1's ceiling on the sensor session's forward.unreachable (section 1.9
// item 5; D6's N2 on #676): with the platform class at the ceiling, the
// sensor session's unreachable alarm stands, but its health event is not
// written and is counted in health_held. Control: reach's sensor branch
// sent through Runtime.health, which writes it.
func TestSensorSessionUnreachableUnderCeiling(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 10, 25, 6, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	c, _ := sensorForwardConfig(t, true, 9) // the forwarders are never run
	st := NewStatus("", nil, clock)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Now: clock, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	waitSensor(t, r)
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	tg := fw.targets[0]
	req := *tg.t
	req.Class = syslog.ClassRequired // as in TestSensorSessionUnreachableNamed
	tg.t = &req
	heldManager(r, func() {
		used, err := r.Store(HealthStream).ClassBytes(bg, c5.ClassPlatform)
		if err != nil {
			t.Fatal(err)
		}
		col, _ := r.cfg.PlatformFloor()
		r.cfg.Store.Quotas["platform"] = used + col + 1 // nothing fits beneath it
	})
	caughtUp := func(open time.Time, ids []c5.StreamID) forward.Status {
		fs := forward.Status{Open: open, Streams: map[c5.StreamID]forward.StreamStatus{}}
		for _, id := range ids {
			if db := r.Store(id); db != nil {
				last, _ := db.LastCommitted(bg, id)
				fs.Streams[id] = forward.StreamStatus{Cursor: last, Confirmed: last}
			}
		}
		return fs
	}
	before := r.sensorHeld.Load()
	sensorDown := caughtUp(time.Time{}, tg.sstreams)
	sensorDown.LastErr = errNotOpenForTest
	fw.checkSessions(bg, tg, caughtUp(clock(), tg.streams), &sensorDown)
	advance(UnreachableAfter + time.Second)
	fw.checkSessions(bg, tg, caughtUp(clock(), tg.streams), &sensorDown)
	n := 0
	for _, a := range st.Snapshot("site-a-node1").Alarms {
		if a.Code == AlarmForwardUnreachable && strings.HasPrefix(a.Detail, SensorSessionPrefix) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d sensor-session forward-unreachable alarms, want 1", n)
	}
	if ev := forwardUnreachableEvents(t, r); len(ev) != 0 {
		t.Fatalf("forward.unreachable written past the ceiling: %v", ev)
	}
	if r.sensorHeld.Load() == before {
		t.Fatal("the sensor session's forward.unreachable was not counted in health_held")
	}
}

var errNotOpenForTest = errors.New("node: the database holding network-alert is not open")

// forwardUnreachableEvents are the details of the forward.unreachable
// health events, in order.
func forwardUnreachableEvents(t *testing.T, r *Runtime) (out []map[string]string) {
	t.Helper()
	got, err := r.Store(HealthStream).Read(bg, HealthStream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		e, err := event.Decode(s.Event)
		if err != nil {
			t.Fatal(err)
		}
		if e.Health.Type == event.HealthForwardUnreachable {
			out = append(out, e.Health.Details)
		}
	}
	return out
}

// D6's B2 on #663: the target's status counts the forward.* reports both
// sessions owe and shows both report errors, so the sensor session's owed
// health events appear in otsec status. Control: the main session's
// values only.
func TestSensorSessionUnreportedShown(t *testing.T) {
	c, dir := sensorForwardConfig(t, true, 9) // the forwarders are never run
	r, st, _ := start(t, c, dir)
	defer r.Close()
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	tg := fw.targets[0]
	sensorErr := SensorSessionPrefix + ": node test: the sensor session's report"
	sensor := forward.Status{Unreported: 2, ReportErr: errors.New("node test: the sensor session's report")}
	fw.checkSessions(bg, tg, forward.Status{Unreported: 1, ReportErr: errors.New("node test: the main session's report")}, &sensor)
	ts := st.Snapshot("site-a-node1").Targets[tg.t.Name]
	if ts.Unreported != 3 || ts.ReportErr != "node test: the main session's report; "+sensorErr {
		t.Fatalf("both sessions owing: unreported %d, want 3; report error %q", ts.Unreported, ts.ReportErr)
	}
	fw.checkSessions(bg, tg, forward.Status{}, &sensor)
	ts = st.Snapshot("site-a-node1").Targets[tg.t.Name]
	if ts.Unreported != 2 || ts.ReportErr != sensorErr {
		t.Fatalf("only the sensor session owing: unreported %d, want 2; report error %q", ts.Unreported, ts.ReportErr)
	}
}
