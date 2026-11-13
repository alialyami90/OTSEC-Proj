package node

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	heldManager(r, func() { r.alertAppend = func([]c5.Record) error { return errors.New("node test: the alert class refuses") } })
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
