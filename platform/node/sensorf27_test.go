package node

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/sensorlink"
)

// Brief P4-4-F27, deliverable (3): F1 (the platform-class floor and
// ceiling), F3 (the detector's drive), F4 (the link's lock, with the
// interim behaviour on a timeout), item 9's recover in the scheduler
// calls, and the items carried from #663. The tests that need this
// package's scheduler or the runtime's own state are here; the rest are in
// sensortest and sensorlink. Desk only: no sensor and no device.

// startClocked starts c on rig g's clocks, with seams s, and waits for the
// sensor manager's first step.
func startClocked(t *testing.T, g *retentionRig, s SensorSeams) (*Runtime, *Status) {
	t.Helper()
	st := NewStatus("", nil, g.now)
	r, err := Start(bg, g.c, RuntimeOptions{Status: st, Now: g.now, Mono: g.monoNow, SensorSeams: s,
		Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	waitSensor(t, r)
	return r, st
}

// The floor's terms (section 1.9 item 5): the worked example, ten entries
// every 600 s over 24 outage hours, gives C = 11,796,480 and S = 4,423,680
// bytes. A quota of C + S starts the sensor and one byte less does not;
// the ceiling admits an event only while the class holds less than quota
// less C after it. Controls: each comparison moved by one, which the
// boundary cases fail.
func TestPlatformFloorTerms(t *testing.T) {
	c := &Config{NetworkSensor: &NetworkSensor{OutageHours: 24}, Store: StoreConfig{Quotas: map[string]int64{}}}
	for range 10 {
		c.Schedule = append(c.Schedule, Collection{EverySeconds: 600})
	}
	col, sen := c.PlatformFloor()
	if col != 11796480 || sen != 4423680 {
		t.Fatalf("C %d, S %d; want 11796480, 4423680", col, sen)
	}
	c.Store.Quotas["platform"] = col + sen
	if short, why := c.platformFloorShort(); short {
		t.Fatalf("a quota of C + S is short: %s", why)
	}
	c.Store.Quotas["platform"] = col + sen - 1
	if short, why := c.platformFloorShort(); !short || !strings.Contains(why, "11796480") || !strings.Contains(why, "4423680") {
		t.Fatalf("a quota one byte below C + S: short %v, %q", short, why)
	}
	if !ceilingFits(99, 1, 200, 99) || ceilingFits(100, 1, 200, 99) {
		t.Fatal("the ceiling's boundary: 99+1 < 200-99 fits, 100+1 does not")
	}
	if a, _ := (&Config{}).PlatformFloor(); a != 0 {
		t.Fatalf("C without the section: %d", a)
	}
}

// F1's start (section 1.9 item 5; TestPlatformFloorShortNodeStarts): a
// platform quota one byte below C + S does not refuse the configuration or
// the start. The node starts and a scheduled run is sent and stores its
// rows; the sensor is not started, so its connection is refused; and
// sensor-platform-floor stands once, naming both terms. Control: a load
// refusal (platformFloorShort checked in Config.check), which fails the
// test at ParseConfig.
func TestPlatformFloorShortNodeStarts(t *testing.T) {
	probe, _ := holdConfig(t)
	col, sen := probe.PlatformFloor()
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
		nc.Store.Quotas["platform"] = col + sen - 1
	})
	r, st := startSeams(t, c, dir, SensorSeams{})
	defer r.Close()
	runSent(t, r)
	sensorStep(t, r)
	if r.sensor.Load() != nil || r.ServeSensor(bg, sensorChannel(t, ownFlow(1))) == nil {
		t.Fatal("the sensor started below its platform floor")
	}
	var detail string
	n := 0
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == AlarmSensorPlatformFloor {
			n, detail = n+1, a.Detail
		}
	}
	if n != 1 || !strings.Contains(detail, "below collection's need") {
		t.Fatalf("%d sensor-platform-floor alarms: %q", n, detail)
	}
}

// F1's ceiling, where each sensor health event goes on main (D6's N3 on
// #662): with the platform class at the ceiling, the network database's
// store alarm is not written to platform/health and is counted in
// health_held, while the evidence database's is written; a sensor mode
// change's health event and the forwarder's sensor session's report are
// held too, while its main session's sink still writes. Control: Tick's
// queue sent through Runtime.health for every database, which writes the
// network database's alarm.
func TestSensorEventsHeldPastCeiling(t *testing.T) {
	c, dir := holdConfig(t)
	r, st := startSeams(t, c, dir, SensorSeams{})
	defer r.Close()
	db := r.Store(HealthStream)
	heldManager(r, func() {
		used, err := db.ClassBytes(bg, c5.ClassPlatform)
		if err != nil {
			t.Fatal(err)
		}
		col, _ := r.cfg.PlatformFloor()
		r.cfg.Store.Quotas["platform"] = used + col + 1 // nothing fits beneath it
	})
	before := r.sensorHeld.Load()
	r.storeAlarm(NetworkDB, c5.Alarm{Code: c5.AlarmQuotaWarning, Class: c5.ClassNetworkObservation})
	r.storeAlarm(EvidenceDB, c5.Alarm{Code: c5.AlarmQuotaWarning, Class: c5.ClassAdapterEvidence})
	r.Tick(bg)
	got := map[string]int{}
	recs, err := db.Read(bg, HealthStream, 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range recs {
		if ev, err := event.Decode(s.Event); err == nil && ev.Health != nil && ev.Health.Type == c5.AlarmQuotaWarning.HealthType() {
			got[ev.Health.Details["database"]]++
		}
	}
	if got[string(EvidenceDB)] != 1 || got[string(NetworkDB)] != 0 {
		t.Fatalf("quota warnings written by database: %v", got)
	}
	r.sensorHealthEvent(bg, c5.HealthModeChanged, map[string]string{"database": string(NetworkDB), "from": "collecting", "to": "drain-only"})
	if _, err := (sensorHealthSink{r}).Emit(bg, event.Health{Type: "forward.text-omitted", Details: map[string]string{"target": "lab-a"}}); !errors.Is(err, errPastCeiling) {
		t.Fatalf("the sensor session's report: %v", err)
	}
	if _, err := (healthSink{r}).Emit(bg, event.Health{Type: "forward.text-omitted", Details: map[string]string{"target": "lab-a"}}); err != nil {
		t.Fatalf("the main session's report: %v", err)
	}
	if n := r.sensorHeld.Load() - before; n != 3 {
		t.Fatalf("%d sensor events held, want 3", n)
	}
	sensorStep(t, r)
	if s := st.Snapshot("x").Sensor; s == nil || s.HealthHeld < 3 {
		t.Fatalf("status: %+v", s)
	}
}

// F3's lag alarm (section 1.9 item 3; TestDetectorLagAlarm): while an
// alert the detector raised can't be committed, it reads nothing more, so
// the oldest observation it has not read ages. network-detector-lag is not
// raised at 60 s of node-clock lag, is raised once past it and not again
// while it lasts, with the lag in status, and the stretch ends once the
// detector catches up. Control: no alarm, which leaves the backlog silent.
func TestDetectorLagAlarm(t *testing.T) {
	c, _ := holdConfig(t)
	g := &retentionRig{t: t, c: c, wall: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), mono: time.Minute}
	r, st := startClocked(t, g, SensorSeams{})
	defer r.Close()
	heldManager(r, func() {
		r.alertAppend = func([]c5.Record) error { return errors.New("node test: the alert class refuses") }
	})
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""), relayFlow(2))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	g.advanceWall(60 * time.Second)
	tick(t, r)
	if n := countAlarms(st, AlarmDetectorLag); n != 0 {
		t.Fatalf("%d lag alarms at 60 s", n)
	}
	g.advanceWall(time.Second)
	tick(t, r)
	g.advanceWall(time.Minute)
	tick(t, r)
	d := detectorStatus(t, st)
	if n := countAlarms(st, AlarmDetectorLag); n != 1 || !d.Lagging || d.LagS < 121 {
		t.Fatalf("%d lag alarms past 60 s, status lag %d s, lagging %v", n, d.LagS, d.Lagging)
	}
	heldManager(r, func() { r.alertAppend = nil })
	tick(t, r)
	if d := detectorStatus(t, st); d.Lagging || d.LagS != 0 || d.Through != 2 {
		t.Fatalf("after catching up: %+v", d)
	}
}

// F3's lag stretch (section 1.9 item 3; D6's N1 on #676): once raised, a
// lag that falls below DetectorLagRaise but stays at or above
// DetectorLagClear keeps the stretch, so the alarm is not raised again
// when the lag rises past 60 s once more. Here the stretch is set and the
// lag held at 45 s. Control: the clear moved to DetectorLagRaise, which
// ends the stretch at 45 s.
func TestDetectorLagStretchKept(t *testing.T) {
	c, _ := holdConfig(t)
	g := &retentionRig{t: t, c: c, wall: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), mono: time.Minute}
	r, st := startClocked(t, g, SensorSeams{})
	defer r.Close()
	heldManager(r, func() {
		r.alertAppend = func([]c5.Record) error { return errors.New("node test: the alert class refuses") }
	})
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""), relayFlow(2))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	heldManager(r, func() { r.detector.lagging = true })
	g.advanceWall(45 * time.Second)
	tick(t, r)
	if d := detectorStatus(t, st); !d.Lagging || d.LagS < 45 || d.LagS >= 60 {
		t.Fatalf("at a lag of 45 s in a stretch: %+v", d)
	}
}

// F3's bounds on one drive (section 1.9 item 3; D6's N1 on #676): a drive
// takes at most DriveObservations, and none once DriveTime has passed
// since its first. Control: a take that never stops, which takes past both.
func TestDriveBounds(t *testing.T) {
	dv, n := newDrive(), 0
	for n <= DriveObservations && dv.take() {
		n++
	}
	if n != DriveObservations || !dv.spent {
		t.Fatalf("a drive took %d observations, spent %v; want %d", n, dv.spent, DriveObservations)
	}
	dv = newDrive()
	if !dv.take() {
		t.Fatal("a new drive took no observation")
	}
	time.Sleep(DriveTime) // the drive's work
	if dv.take() {
		t.Fatalf("a drive took an observation %s after its first", DriveTime)
	}
}

// D4's B1 on #676: the drive's clock starts at its first observation, so
// a drive whose work before it takes longer than DriveTime (here the test
// sleeps between newDrive and the drive, as a slow flushAlerts or health
// scan would) still takes one, and Through advances over three drives.
// Each observation is slow too, so a drive takes one and the backlog
// lasts the three drives. Control: the clock started at newDrive, under
// which each drive takes none and Through stays.
func TestDriveSlowBeforeFirstTake(t *testing.T) {
	c, dir := holdConfig(t)
	var slow atomic.Bool
	r, _ := startSeams(t, c, dir, SensorSeams{Observe: func() {
		if slow.Load() {
			time.Sleep(DriveTime + 50*time.Millisecond)
		}
	}})
	defer r.Close()
	heldManager(r, func() {
		slow.Store(true)
		defer slow.Store(false)
		if err := r.ServeSensor(bg, sensorChannel(t, relayFlow(1), relayFlow(2), relayFlow(3))); err != nil {
			t.Fatal(err)
		}
		nd := r.detector
		for i := range 3 {
			before := nd.d.Through()
			dv := newDrive()
			time.Sleep(DriveTime + 50*time.Millisecond) // the work before the first take
			r.driveDetector(bg, nd, dv)
			if nd.d.Through() <= before {
				t.Fatalf("drive %d: Through stayed at %d after slow work before the first take", i, before)
			}
		}
	})
}

// F3's yield (section 1.9 item 3; D6's N1 on #676): a drive that reaches
// DriveTime stops, and a step Tick asked for during it begins before the
// detector takes another observation. The first observation is slow
// (longer than DriveTime) and asks for a step; the second must come after
// that step began. Control: a take that never stops, under which the
// second observation comes in the same drive.
func TestStepBeforeNextDrive(t *testing.T) {
	c, dir := holdConfig(t)
	var r *Runtime
	var calls atomic.Int32
	var begunAt uint64
	late := make(chan bool, 1)
	r, _ = startSeams(t, c, dir, SensorSeams{Observe: func() {
		m := r.smgr
		m.stepMu.Lock()
		begun := m.begun
		m.stepMu.Unlock()
		switch calls.Add(1) {
		case 1:
			begunAt = begun
			r.kickSensorManager()
			time.Sleep(DriveTime + 50*time.Millisecond)
		case 2:
			late <- begun > begunAt
		}
	}})
	defer r.Close()
	if err := r.ServeSensor(bg, sensorChannel(t, relayFlow(1), relayFlow(2))); err != nil {
		t.Fatal(err)
	}
	r.kickSensorManager()
	select {
	case ok := <-late:
		if !ok {
			t.Fatal("the second observation came before the step asked for during the drive")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the detector did not reach a second observation")
	}
}

// advanceWall moves the rig's wall clock only.
func (g *retentionRig) advanceWall(d time.Duration) {
	g.mu.Lock()
	g.wall = g.wall.Add(d)
	g.mu.Unlock()
}

// F3 (section 1.9 item 3; TestTickReturnsWithSlowDetector): with the
// detector stuck on an observation, Tick returns, again and again, and the
// node's own databases take appends and stay collecting. Control:
// tickSensor inside Tick, as on main, where Tick waits for the detector.
func TestTickReturnsWithSlowDetector(t *testing.T) {
	c, dir := holdConfig(t)
	stuck, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r, _ := startSeams(t, c, dir, SensorSeams{Observe: func() {
		once.Do(func() { close(stuck) })
		<-release
	}})
	defer r.Close()
	defer close(release)
	if err := r.ServeSensor(bg, sensorChannel(t, relayFlow(1))); err != nil {
		t.Fatal(err)
	}
	r.kickSensorManager()
	select {
	case <-stuck:
	case <-time.After(10 * time.Second):
		t.Fatal("the detector was not reached")
	}
	for i := range 3 {
		done := make(chan struct{})
		go func() { r.Tick(bg); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("Tick %d did not return within 5 s with the detector stuck", i)
		}
	}
	if _, err := r.Log(HealthStream).Append(bg, mustHealth(t, r)); err != nil || r.Mode(EvidenceDB) != c5.ModeCollecting {
		t.Fatalf("the evidence database: %v, %s", err, r.Mode(EvidenceDB))
	}
}

func mustHealth(t *testing.T, r *Runtime) c5.Record {
	t.Helper()
	rec, err := r.healthRecord(HealthStream, "node.test", map[string]string{"n": "1"})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// F3 for the retention consumer (section 1.9 item 3; D1's point 4 on
// #676): with the network database stalled on a retention call, Tick
// returns, again and again, and a collection still runs through to its
// collection.run. Control: tickRetention inside Tick, where Tick waits
// for the stalled call.
func TestTickReturnsWithStalledRetention(t *testing.T) {
	c, dir := holdConfig(t)
	var stall atomic.Bool
	stuck, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r, _ := startSeams(t, c, dir, SensorSeams{Retention: func(context.Context) {
		if stall.Load() {
			once.Do(func() { close(stuck) })
			<-release
		}
	}})
	defer r.Close()
	defer close(release)
	if r.retention == nil {
		t.Fatal("the first step did not start the retention consumer")
	}
	stall.Store(true)
	ticked := make(chan struct{})
	go func() {
		defer close(ticked)
		for range 3 {
			r.Tick(bg)
		}
	}()
	select {
	case <-stuck:
	case <-time.After(10 * time.Second):
		t.Fatal("the retention call was not reached")
	}
	select {
	case <-ticked:
	case <-time.After(5 * time.Second):
		t.Fatal("Tick did not return within 5 s with the retention call stalled")
	}
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" {
		t.Fatalf("a run with the retention call stalled: %+v", rep)
	}
	if n := len(healthRuns(t, r)); n != 1 {
		t.Fatalf("%d collection.run events, want 1", n)
	}
}

// A stop that lands in a full step (section 1.9 items 3 and 10; D6's
// comment 6862658408 on #676): the step is held in its retention call
// until the stop cancels it, and the stop's final step still writes the
// drop counts and the detector's checkpoint. The next start is held in its
// first step, before the sensor's tick, so what it reads is what the stop
// wrote. Control: the manager's loop returns on a failed step without the
// final step, as at 9d462ba1.
func TestStopInStepStillFinal(t *testing.T) {
	g := newRetentionRig(t)
	var hold atomic.Bool
	entered := make(chan struct{}, 1)
	seam := SensorSeams{Retention: func(ctx context.Context) {
		if hold.Load() {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-ctx.Done()
		}
	}}
	r, _ := startClocked(t, g, seam)
	serve := func(recs ...any) {
		t.Helper()
		if err := r.ServeSensor(bg, sensorChannel(t, recs...)); err != nil {
			t.Fatal(err)
		}
	}
	serve(sensorFlow(1, sensorID), sensorFlow(2, sensorID), relayFlow(3))
	tick(t, r) // the first drop counts and a checkpoint
	// Within the minute: written only at the stop.
	serve(sensorFlow(4, sensorID), sensorFlow(5, sensorID), relayFlow(6))
	want := r.sensor.Load().link.Stats().Dropped[sensorlink.DropUnresolvedBudget]
	obs := NetObservationStream(sensorID)
	head, err := r.Store(obs).LastCommitted(bg, obs)
	if err != nil || head < 2 {
		t.Fatalf("observation head %d, %v", head, err)
	}
	hold.Store(true)
	r.kickSensorManager()
	<-entered
	r.Close()

	// The next start, held in its first step's retention call.
	st := NewStatus("", nil, g.now)
	r2, err := Start(bg, g.c, RuntimeOptions{Status: st, Now: g.now, Mono: g.monoNow, SensorSeams: seam,
		Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the next start's first step did not reach the retention call")
	}
	ev := dropEvents(t, r2)
	if len(ev) != 2 || ev[1]["count"] != strconv.FormatUint(want, 10) {
		t.Errorf("drop counts after a stop in a step, want a second event with %d: %v", want, ev)
	}
	if c := detectorCursor(t, r2); c != head {
		t.Fatalf("the detector's stored cursor is %d after a stop in a step, want the head %d", c, head)
	}
}

// ownSession is the ok-0.9 fixture's session, which ownFlow lies in.
var ownSession = sessionResult{Connected: true, StartedAt: "2026-10-24T09:15:00Z", EndedAt: "2026-10-24T09:15:01.8Z",
	LocalAddr: "192.0.2.10:49152", ConnectedAt: "2026-10-24T09:15:00.05Z"}

// relayFlow is a flow to the relay from an address not the node's: it is
// resolved, so it commits at once on the read loop, untied.
func relayFlow(seq int) *netobs.Observation {
	o := sensorFlow(seq, sensorID)
	p := 2323
	o.IP.Dst, o.IP.Dport = "127.0.0.1", &p
	return o
}

// outsideRecord counts the committed own-session-outside-record alerts.
func outsideRecord(t *testing.T, r *Runtime) (n int) {
	t.Helper()
	for _, a := range committedAlerts(t, r) {
		if a.alert.Rule == netobs.RuleOwnSessionOutsideRecord {
			n++
		}
	}
	return n
}

// F4's interim behaviour (section 1.9 item 4, brief P4-4-F27): a Result
// that does not have the link's lock within HoldLockWait, here because the
// read loop is in a network commit that does not end, gives up. The run
// goes on with no session in its collection.run, result_timeouts rises and
// network-session-not-tied stands; the run's own flow commits untied at
// its deadline, and the base rules judge it: own-session-outside-record.
// sensor-failed is not raised. Control: a Result that waits for the lock
// with no bound (D3's condition broken: the timed-out session treated as
// tied), which ties the flow once the commit ends, so no alert is raised.
func TestResultTimeoutUntiedJudged(t *testing.T) {
	c, _ := holdConfig(t)
	g := &retentionRig{t: t, c: c, wall: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), mono: time.Minute}
	var block atomic.Bool
	gate, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := sync.OnceFunc(func() { close(gate) })
	r, st := startClocked(t, g, SensorSeams{Append: func(context.Context) {
		if block.Load() {
			once.Do(func() { close(entered) })
			<-gate
		}
	}})
	defer r.Close()
	defer release()
	s := newScheduler(t, r, &fakeCollector{})
	h := s.dispatchHold(bg, c.Schedule[0], s.newID())
	if h == nil {
		t.Fatal("the hold doesn't watch the run")
	}
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	block.Store(true)
	served := make(chan error, 1)
	go func() { served <- r.ServeSensor(bg, sensorChannel(t, relayFlow(2))) }()
	<-entered
	go func() { time.Sleep(3 * sensorlink.HoldLockWait); release() }() // so a control ends
	from := time.Now()
	got := s.resultHold(bg, h, okInvocation, ownSession)
	if took := time.Since(from); got != nil || took < sensorlink.HoldLockWait || took > 2*sensorlink.HoldLockWait {
		t.Fatalf("result after %s: session %v; want none, after %s", took, got, sensorlink.HoldLockWait)
	}
	block.Store(false)
	release()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	s.recordedRun(bg, h)
	g.advance(sensorlink.HoldRunLimit + netobs.DefaultTieGraceS*time.Second + time.Second)
	tick(t, r)
	tick(t, r)
	sn := st.Snapshot("x").Sensor
	if sn == nil || sn.ResultTimeouts != 1 || countAlarms(st, AlarmNetworkSessionNotTied) != 1 || countAlarms(st, AlarmSensorFailed) != 0 {
		t.Fatalf("status %+v, %d not-tied, %d sensor-failed", sn, countAlarms(st, AlarmNetworkSessionNotTied), countAlarms(st, AlarmSensorFailed))
	}
	if n := outsideRecord(t, r); n != 1 {
		t.Fatalf("%d own-session-outside-record alerts on the untied run's flow, want 1", n)
	}
}

// Item 9 in the scheduler calls (section 1.9 item 9): a panic inside
// Result while it holds the link's lock, here in the intake hold's save of
// the release, is recovered and taken as a timeout. The run goes on with
// no session, result_timeouts rises and network-session-not-tied stands,
// sensor-failed is not raised, the sensor's work goes on (a later
// connection is served), and the run's flow commits untied at its deadline
// and alerts. Control: no recover in schedCall, which ends the process.
func TestSchedulerPanicTakenAsTimeoutUntied(t *testing.T) {
	c, _ := holdConfig(t)
	g := &retentionRig{t: t, c: c, wall: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), mono: time.Minute}
	var boom atomic.Bool
	r, st := startClocked(t, g, SensorSeams{SaveIntake: func() {
		if boom.Load() {
			panic("node test: a fault in the release's save")
		}
	}})
	defer r.Close()
	s := newScheduler(t, r, &fakeCollector{})
	h := s.dispatchHold(bg, c.Schedule[0], s.newID())
	if h == nil {
		t.Fatal("the hold doesn't watch the run")
	}
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	boom.Store(true)
	if got := s.resultHold(bg, h, okInvocation, ownSession); got != nil {
		t.Fatalf("session details after a panic: %v", got)
	}
	boom.Store(false)
	s.recordedRun(bg, h)
	if err := r.ServeSensor(bg, sensorChannel(t, relayFlow(2))); err != nil {
		t.Fatalf("the sensor's work stopped: %v", err)
	}
	g.advance(sensorlink.HoldRunLimit + netobs.DefaultTieGraceS*time.Second + time.Second)
	tick(t, r)
	tick(t, r)
	sn := st.Snapshot("x").Sensor
	if sn == nil || sn.ResultTimeouts != 1 || countAlarms(st, AlarmNetworkSessionNotTied) != 1 || countAlarms(st, AlarmSensorFailed) != 0 || r.sensorFailed.Load() {
		t.Fatalf("status %+v, %d not-tied, %d sensor-failed", sn, countAlarms(st, AlarmNetworkSessionNotTied), countAlarms(st, AlarmSensorFailed))
	}
	if n := outsideRecord(t, r); n != 1 {
		t.Fatalf("%d own-session-outside-record alerts, want 1", n)
	}
}

// D6's item 3 on #663: a published intake appends nothing while the
// network database is in a mode that accepts no new events, here
// drain-only as a retry can bring it back; the record is dropped and
// counted under store. Control: liveAppender with no mode check, which
// commits it.
func TestLiveAppenderDrainOnlyDrops(t *testing.T) {
	c, dir := holdConfig(t)
	r, _ := startSeams(t, c, dir, SensorSeams{})
	defer r.Close()
	d := r.find(NetworkDB)
	heldManager(r, func() {
		r.smu.Lock()
		d.report.Mode = c5.ModeDrainOnly
		r.smu.Unlock()
	})
	if err := r.ServeSensor(bg, sensorChannel(t, relayFlow(1))); err != nil {
		t.Fatal(err)
	}
	st := r.sensor.Load().link.Stats()
	heldManager(r, func() {
		r.smu.Lock()
		d.report.Mode = c5.ModeCollecting
		r.smu.Unlock()
	})
	if st.Committed != 0 || st.Dropped[sensorlink.DropStore] != 1 {
		t.Fatalf("with the network database drain-only: %d committed, drops %v", st.Committed, st.Dropped)
	}
}

// Holds after sensor-failed (carried from #663): once the sensor's work
// has failed, a run holds nothing, since nothing would give its flows way,
// and a Result does not call the link. Control: dispatchHold with no
// sensorFailed check, which holds the run.
func TestNoHoldAfterSensorFailed(t *testing.T) {
	c, dir := holdConfig(t)
	r, _ := startSeams(t, c, dir, SensorSeams{})
	defer r.Close()
	s := newScheduler(t, r, &fakeCollector{})
	r.sensorFailed.Store(true)
	if h := s.dispatchHold(bg, c.Schedule[0], s.newID()); h != nil {
		t.Fatal("a run was held after sensor-failed")
	}
	if st := r.sensor.Load().link.Stats(); st.Hold.Runs != 0 {
		t.Fatalf("hold %+v", st.Hold)
	}
}

// D6's note 1 on #663, the after_seq: a Result while the network database
// is swapped out for a Resume reads no head after its release, so the
// run's collection.run carries no session rather than after_seq 0, and the
// detector meets no ordering fault. Control: the head's error dropped in
// sensorlink's release, which hands on after_seq 0.
func TestResultWhileNetworkSwappedOut(t *testing.T) {
	c, dir := holdConfig(t)
	r, st := startSeams(t, c, dir, SensorSeams{})
	defer r.Close()
	s := newScheduler(t, r, &fakeCollector{})
	h := s.dispatchHold(bg, c.Schedule[0], s.newID())
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	d := r.find(NetworkDB)
	var got map[string]string
	heldManager(r, func() {
		r.smu.Lock()
		d.out = true
		r.smu.Unlock()
		got = s.resultHold(bg, h, okInvocation, ownSession)
		r.smu.Lock()
		d.out = false
		r.smu.Unlock()
	})
	if got != nil {
		t.Fatalf("session details with the database swapped out: %v", got)
	}
	s.recordedRun(bg, h)
	tick(t, r)
	if d := detectorStatus(t, st); d.OrderingFaults != 0 || countAlarms(st, AlarmDetectorOrdering) != 0 {
		t.Fatalf("detector %+v", d)
	}
}
