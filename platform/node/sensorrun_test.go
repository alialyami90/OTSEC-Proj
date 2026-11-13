package node

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/sensorlink"
	"otsec.local/otsec/platform/store"
)

// The sensor manager's tests that need the scheduler's test collector or
// the intake's own records, which only this package's tests have (brief
// P4-4-F27; D6's review of #663). Desk only: no sensor and no device.

// startSeams starts the node with seams s and waits for the manager's
// first step.
func startSeams(t *testing.T, c *Config, dir string, s SensorSeams) (*Runtime, *Status) {
	t.Helper()
	st := NewStatus(filepath.Join(dir, "status.json"), nil, nil)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}, BusyTimeout: heldBusyTimeout, SensorSeams: s})
	if err != nil {
		t.Fatal(err)
	}
	waitSensor(t, r)
	return r, st
}

// failFirstOpen is a Startup seam whose first startup's store is closed
// before the node reads it, so the network database does not open.
func failFirstOpen(opens *atomic.Int32) func(context.Context, c5.StartupEnv, c5.StartupPolicy) c5.Report {
	return func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
		rep := c5.RunStartup(ctx, env, p)
		if opens.Add(1) == 1 {
			if db, ok := store.AsDB(rep.Store); ok {
				db.Close()
			}
		}
		return rep
	}
}

// interruptRelease dispatches a run, holds one of its flows, and writes a
// releasing record for it with nothing committed, as a crash between the
// releasing record and its batch leaves it; seq is the flow's.
func interruptRelease(t *testing.T, r *Runtime, seq int) {
	t.Helper()
	s := newScheduler(t, r, &fakeCollector{})
	if s.dispatchHold(bg, r.cfg.Schedule[0], s.newID()) == nil {
		t.Fatal("the hold doesn't watch the run")
	}
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(seq))); err != nil {
		t.Fatal(err)
	}
	_, docs := intakeDocs(t, r)
	held := docs[len(docs)-1]
	if held.State != sensorlink.HoldHolding || len(held.Flows) != 1 {
		t.Fatalf("holding record: %+v", held)
	}
	// Head is the observation stream's head when the release began: the
	// batch commits only while it still is.
	head := r.lastSeq(bg, NetObservationStream(sensorID))
	held.State, held.Releasing, held.Head = sensorlink.HoldReleasing, []sensorlink.Release{{Record: held.Flows[0].Records[0]}}, head
	held.Flows = []sensorlink.HeldFlow{}
	b, err := json.Marshal(held)
	if err != nil {
		t.Fatal(err)
	}
	stream := r.intakeStream()
	if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: b}); err != nil {
		t.Fatal(err)
	}
}

// repairedRuns counts the collection.run records of request id, and those
// repaired from the intake.
func repairedRuns(t *testing.T, r *Runtime, id string) (runs, repaired int) {
	t.Helper()
	for _, h := range healthRuns(t, r) {
		e, _ := event.Decode(h.Event)
		if e.Health.Details["request_id"] != id {
			continue
		}
		runs++
		if e.Health.Details["repaired_from"] == RepairedFromIntake {
			repaired++
		}
	}
	return runs, repaired
}

// F2's retry (D6's B2 on #663): a crash after a run's release, and a crash
// inside another run's release; then a restart whose network database
// fails its first open, so the intake does not start at the first step.
// The next tick's step opens the database and starts the intake: its
// RecoverHold commits the interrupted release once, and its repairIntake
// writes the crashed run's collection.run once. Control: a retry that
// skips RecoverHold and repairIntake (D6's MUT-A).
func TestIntakeRetryRecoversAndRepairs(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	id := crashAfterRelease(t, r, audit.OutcomeAllowed, false)
	interruptRelease(t, r, 3)
	before := len(observations(t, r))
	r.Close()

	var opens atomic.Int32
	r, st := startSeams(t, c, dir, SensorSeams{Startup: failFirstOpen(&opens)})
	defer r.Close()
	if r.sensor.Load() != nil || countAlarms(st, AlarmSensorIntakeNotStarted) != 1 {
		t.Fatalf("intake at the first step: started %v", r.sensor.Load() != nil)
	}
	if runs, _ := repairedRuns(t, r, id); runs != 0 {
		t.Fatalf("%d collection.run before the retry", runs)
	}
	tick(t, r)
	for deadline := time.Now().Add(10 * time.Second); r.sensor.Load() == nil; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the intake did not start at the tick")
		}
	}
	if runs, repaired := repairedRuns(t, r, id); runs != 1 || repaired != 1 {
		t.Fatalf("crashed run %s after the retry: %d collection.run, %d repaired", id, runs, repaired)
	}
	if n := len(observations(t, r)); n != before+1 {
		t.Fatalf("%d observations after the retry, want %d: the interrupted release committed once", n, before+1)
	}
}

// The intake is published only after its hold is recovered (D6's MUT-B):
// a try whose RecoverHold fails leaves no intake for the scheduler to
// reach. The network database is drain-only at the first step, so the
// intake waits; the tick's Resume makes it collecting over a store that
// cannot be read, so the second try reaches RecoverHold, which fails on the
// interrupted release's observation head. Control: the intake published
// before RecoverHold, main's order.
func TestIntakeNotPublishedOnFailedRecovery(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	interruptRelease(t, r, 1)
	r.Close()

	r, st := startSeams(t, c, dir, SensorSeams{
		Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
			rep := c5.RunStartup(ctx, env, p)
			if rep.Mode == c5.ModeCollecting {
				rep.Mode = c5.ModeDrainOnly
			}
			return rep
		},
		Resume: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report {
			if db, ok := store.AsDB(prev.Store); ok {
				db.Close()
			}
			prev.Mode = c5.ModeCollecting
			return prev
		}})
	defer r.Close()
	if r.sensor.Load() != nil || countAlarms(st, AlarmSensorIntakeNotStarted) != 1 {
		t.Fatalf("intake at the first step: started %v", r.sensor.Load() != nil)
	}
	tick(t, r)
	for deadline := time.Now().Add(10 * time.Second); r.smgr.steps.Load() < 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the tick's step did not end")
		}
	}
	if r.Mode(NetworkDB) != c5.ModeCollecting {
		t.Fatalf("network database %s", r.Mode(NetworkDB))
	}
	if r.sensor.Load() != nil {
		t.Fatal("the intake was published although its RecoverHold failed")
	}
}

// heldResume is a Startup seam that leaves the network database drain-only
// and a Resume seam that holds until released.
func heldResume() (SensorSeams, chan struct{}, func()) {
	in, release := make(chan struct{}), make(chan struct{})
	var once, rel sync.Once
	return SensorSeams{
		Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
			rep := c5.RunStartup(ctx, env, p)
			if rep.Mode == c5.ModeCollecting {
				rep.Mode = c5.ModeDrainOnly
			}
			return rep
		},
		Resume: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report {
			once.Do(func() { close(in); <-release })
			return c5.Resume(ctx, env, p, prev)
		}}, in, func() { rel.Do(func() { close(release) }) }
}

// runSent runs one scheduled run through the test collector and checks
// that it is sent within 2 s and stores its SER rows.
func runSent(t *testing.T, r *Runtime) {
	t.Helper()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	done := make(chan Report, 1)
	go func() { done <- s.RunOnce(bg, 0) }()
	var rep Report
	select {
	case rep = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the run did not return within 2 s")
	}
	if !rep.Sent || rep.Outcome != "ok" || rep.Events == 0 {
		t.Fatalf("run: %+v", rep)
	}
	ser, err := r.Store(SERStream(relayID)).Read(bg, SERStream(relayID), 0, 1000)
	if err != nil || len(ser) != rep.Events {
		t.Fatalf("SER: %d, %v; the run says %d", len(ser), err, rep.Events)
	}
}

// F5's scheduled-run leg (D6 on #663): while the network database's Resume
// is held on the manager's goroutine, a scheduled run is sent within 2 s
// and stores its SER rows. The intake is not started (the database was
// drain-only), so the run is untied. Control: the sensor database back in
// Runtime.dbs, where Tick resumes it under the state lock.
func TestRunWhileSensorResumeHeld(t *testing.T) {
	c, dir := holdConfig(t)
	seams, in, release := heldResume()
	r, _ := startSeams(t, c, dir, seams)
	t.Cleanup(func() { r.Close() })
	t.Cleanup(release)
	go r.Tick(bg)
	select {
	case <-in:
	case <-time.After(10 * time.Second):
		t.Fatal("the network database's Resume was not reached")
	}
	runSent(t, r)
}

// Item 9's run leg (D6 on #663): after a panic on the manager's goroutine
// is recovered as sensor-failed, a scheduled run is still sent and stores
// its rows. Control: no recover, which ends the process.
func TestRunAfterSensorFailed(t *testing.T) {
	c, dir := holdConfig(t)
	r, st := startSeams(t, c, dir, SensorSeams{
		Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
			rep := c5.RunStartup(ctx, env, p)
			if rep.Mode == c5.ModeCollecting {
				rep.Mode = c5.ModeDrainOnly
			}
			return rep
		},
		Resume: func(context.Context, c5.StartupEnv, c5.StartupPolicy, c5.Report) c5.Report {
			panic("node test: a fault in the sensor's work")
		}})
	defer r.Close()
	tick(t, r)
	for deadline := time.Now().Add(10 * time.Second); countAlarms(st, AlarmSensorFailed) == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("sensor-failed was not raised")
		}
	}
	runSent(t, r)
	if n := countAlarms(st, AlarmSensorFailed); n != 1 {
		t.Fatalf("%d sensor-failed alarms", n)
	}
}

// D6's C2 on #663: a store's Alarms callback calls sensorStartupAlarm on
// the goroutine that commits, while the manager's step ends a stretch
// (forgetRaised) on its own. Both run here at once, many times, and the
// alarm is raised and recorded for its stretch. Control: no lock around
// m.raised, where the runtime stops the process with a concurrent map
// read and write, which recover does not catch.
func TestSensorStartupAlarmConcurrent(t *testing.T) {
	c, dir := holdConfig(t)
	r, st := startSeams(t, c, dir, SensorSeams{})
	defer r.Close()
	var wg sync.WaitGroup
	const n = 20000
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range n {
			r.sensorStartupAlarm(NetworkDB, c5.Alarm{Code: c5.AlarmQuotaWarning, At: time.Now(), Detail: "node test: a commit's quota warning"})
		}
	}()
	go func() {
		defer wg.Done()
		for range n {
			r.smgr.forgetRaised(NetworkDB)
		}
	}()
	wg.Wait()
	if countAlarms(st, string(c5.AlarmQuotaWarning)) == 0 {
		t.Fatal("no quota warning raised")
	}
	r.sensorStartupAlarm(NetworkDB, c5.Alarm{Code: c5.AlarmQuotaWarning, At: time.Now(), Detail: "node test: after the race"})
	r.smgr.raisedMu.Lock()
	raised := r.smgr.raised[NetworkDB][c5.AlarmQuotaWarning]
	r.smgr.raisedMu.Unlock()
	if !raised {
		t.Fatal("the stretch's alarm is not recorded as raised")
	}
}
