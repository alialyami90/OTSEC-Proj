package sensortest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/store"
)

// gate is a seam that blocks its first caller until released, and tells
// the test when that caller is in it.
type gate struct {
	in      chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func newGate() *gate { return &gate{in: make(chan struct{}), release: make(chan struct{})} }

// wait blocks the first call until release; later calls pass at once.
func (g *gate) wait() {
	if g.calls.Add(1) == 1 {
		close(g.in)
		<-g.release
	}
}

func (g *gate) open() { g.once.Do(func() { close(g.release) }) }

// entered waits up to 10 s for the first caller.
func (g *gate) entered(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.in:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s was not reached within 10 s", what)
	}
}

// F5 (section 1.9 item 1): a sensor database held drain-only, whose Resume
// does not return, holds neither the state lock that every Log, Store and
// Mode call of the scheduler and the Syslog intake takes, nor Tick, nor
// the sensor database's own accessor. While it is held: Tick returns,
// appends to platform/health, the audit stream and the listener's stream
// commit within 2 s, the evidence database's mode reads, and the sensor's
// alert stream reads as not open at once. Released, the database resumes
// to collecting. Controls: the sensor database back in Runtime.dbs, where
// Tick resumes it under the state lock (main's Tick); and the manager's
// lock held across Resume.
func TestSensorDrainOnlyDoesNotStallSyslog(t *testing.T) {
	g := newRig(t)
	resume := newGate()
	r, _ := g.start(node.SensorSeams{Startup: drainOnly,
		Resume: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report {
			resume.wait()
			return c5.Resume(ctx, env, p, prev)
		}})
	// The gate opens before Close, so a control that holds Close behind it ends.
	t.Cleanup(func() { r.Close() })
	t.Cleanup(resume.open)
	if m := r.Mode(node.NetworkDB); m != c5.ModeDrainOnly {
		t.Fatalf("network database %s", m)
	}
	ticked := make(chan struct{})
	go func() { r.Tick(bg); close(ticked) }()
	resume.entered(t, "the sensor database's Resume")
	select {
	case <-ticked:
	case <-time.After(2 * time.Second):
		t.Fatal("Tick did not return within 2 s while a sensor database's Resume runs")
	}
	collecting(t, r, 1)
	within(t, 2*time.Second, "the sensor's accessor", func() error {
		if r.Store(node.NetAlertStream(sensorID)) != nil {
			return errorf("the alert stream's database reads as open while it resumes")
		}
		return nil
	})
	resume.open()
	eventually(t, "the network database resumed", func() bool {
		return r.Mode(node.NetworkDB) == c5.ModeCollecting && r.Store(node.NetAlertStream(sensorID)) != nil
	})
}

// F6 (section 1.9 item 1): a sensor database's prune that does not return
// holds no prune of the node's own databases. Runtime.Prune, which the
// scheduler's cannotKeep calls before it holds a run when adapter-evidence
// is near its limit, returns within 2 s, and so does Tick. The seam runs
// before the sensor database's prune passes, so no class needs to be
// over its target. Control: Prune over the sensor store set as well
// (main's Prune).
func TestCannotKeepPrunesEvidenceOnly(t *testing.T) {
	g := newRig(t)
	prune := newGate()
	// Not waited for: the manager's first step ends with the prune it holds.
	r, _ := g.startNoWait(node.SensorSeams{Prune: func(context.Context, c5.DatabaseID) error { prune.wait(); return nil }})
	// The gate opens before Close, so a control that holds Close behind it ends.
	t.Cleanup(func() { r.Close() })
	t.Cleanup(prune.open)
	within(t, 2*time.Second, "Tick", func() error { r.Tick(bg); return nil })
	prune.entered(t, "the sensor database's prune")
	within(t, 2*time.Second, "Runtime.Prune while a sensor database's prune is held", func() error { r.Prune(bg); return nil })
	collecting(t, r, 1)
	prune.open()
}

// F7 (section 1.9 item 1): a network database that opens and then fails
// its first read does not fail the node's start. The node starts, raises
// sensor-store-not-open once, and collects; the database reads as not
// open. The manager tries again at each tick: a second failed try raises
// nothing more, and the third opens it. Controls: the sensor database back
// in Runtime.dbs (main's startDB, whose failure fails Start); the alarm
// raised at every try (D6's MUT-E).
func TestSensorStoreFailsOpenNodeStarts(t *testing.T) {
	g := newRig(t)
	var opens atomic.Int32
	r, st := g.start(node.SensorSeams{Startup: failReads(&opens, 2)})
	defer r.Close()
	if n := alarms(st, string(node.AlarmSensorStoreNotOpen)); n != 1 || r.Mode(node.NetworkDB) != c5.ModeFailed || r.Store(node.NetAlertStream(sensorID)) != nil {
		t.Fatalf("%d not-open alarms, mode %s", n, r.Mode(node.NetworkDB))
	}
	collecting(t, r, 1)
	r.Tick(bg)
	eventually(t, "the second try", func() bool { return opens.Load() == 2 })
	// The third try starts only once the second's step has ended.
	r.Tick(bg)
	eventually(t, "the network database opened at the third try", func() bool {
		return r.Mode(node.NetworkDB) == c5.ModeCollecting && r.Store(node.NetAlertStream(sensorID)) != nil
	})
	if n := alarms(st, string(node.AlarmSensorStoreNotOpen)); n != 1 || opens.Load() != 3 {
		t.Fatalf("%d not-open alarms, %d opens", n, opens.Load())
	}
}

// failFirstRead is failReads for the first startup only.
func failFirstRead(opens *atomic.Int32) func(context.Context, c5.StartupEnv, c5.StartupPolicy) c5.Report {
	return failReads(opens, 1)
}

// failReads is a Startup seam: the first n startups' stores are closed
// before the node reads them, so the node's first read of each fails;
// later startups are C5's.
func failReads(opens *atomic.Int32, n int32) func(context.Context, c5.StartupEnv, c5.StartupPolicy) c5.Report {
	return func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
		rep := c5.RunStartup(ctx, env, p)
		if opens.Add(1) <= n {
			if db, ok := store.AsDB(rep.Store); ok {
				db.Close()
			}
		}
		return rep
	}
}

// F2 (section 1.9 item 2): the intake's start is retried by the manager.
// With the network database not open at start, the intake does not start:
// sensor-intake-not-started is raised once and the sensor is refused. At
// the next tick the manager opens the database and starts the intake,
// which runs loadIntake, Link.RecoverHold and repairIntake, and the sensor
// is served. Control: the intake started at Start only, with no retry.
func TestIntakeStartRetried(t *testing.T) {
	g := newRig(t)
	var opens atomic.Int32
	r, st := g.start(node.SensorSeams{Startup: failFirstRead(&opens)})
	defer r.Close()
	if n := alarms(st, node.AlarmSensorIntakeNotStarted); n != 1 {
		t.Fatalf("%d intake alarms", n)
	}
	if err := r.ServeSensor(bg, bytes.NewReader(nil)); err == nil {
		t.Fatal("the sensor was served with the intake not started")
	}
	r.Tick(bg)
	eventually(t, "the intake started at a later tick", func() bool { return r.ServeSensor(bg, bytes.NewReader(nil)) == nil })
	if n := alarms(st, node.AlarmSensorIntakeNotStarted); n != 1 {
		t.Fatalf("%d intake alarms after the retry", n)
	}
}

// F9 (section 1.9 item 1): a sensor database's mode changes write at most
// one store.mode_change record and one mode_changed health event an hour,
// on the node's monotonic clock; the next record says how many were not
// written. Six changes within the hour after the start's record write
// nothing; a seventh after the wall clock alone moves two hours writes
// nothing either; the first after the monotonic hour writes one, naming
// the eight before it. Controls: the cap removed; the cap on the wall
// clock (D6's MUT-F).
func TestSensorModeChangeCapped(t *testing.T) {
	g := newRig(t)
	// The database flaps between blocked, at each startup, and failed, at
	// each Resume; the manager starts a failed one again. ("drain-only"
	// is not used: C8's reason-code pattern refuses it, so main writes no
	// audit record for that mode at all.)
	r, st := g.start(node.SensorSeams{
		Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
			rep := c5.RunStartup(ctx, env, p)
			if db, ok := store.AsDB(rep.Store); ok {
				db.Close()
			}
			return c5.Report{Mode: c5.ModeBlocked, Unlock: rep.Unlock}
		},
		Resume: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report {
			return c5.Report{Mode: c5.ModeFailed, Unlock: prev.Unlock}
		}})
	defer r.Close()
	flap := func() {
		t.Helper()
		was := r.Mode(node.NetworkDB)
		r.Tick(bg)
		eventually(t, "a mode change", func() bool { return r.Mode(node.NetworkDB) != was })
	}
	if recs, evs := modeChanges(t, r, node.NetworkDB); len(recs) != 1 || len(evs) != 1 {
		t.Fatalf("at start: %d records, %d events; %+v", len(recs), len(evs), st.Snapshot("x").Alarms)
	}
	for range 6 {
		g.advance(time.Minute)
		flap()
	}
	g.advanceWall(2 * time.Hour)
	flap()
	// A change is seen only once the manager has finished the step before
	// it, so every record the seven before could write is written by now.
	g.advance(time.Minute)
	flap()
	if recs, evs := modeChanges(t, r, node.NetworkDB); len(recs) != 1 || len(evs) != 1 {
		t.Fatalf("seven changes within the monotonic hour, one after a wall-clock step: %d records, %d events", len(recs), len(evs))
	}
	g.advanceMono(time.Hour)
	flap()
	eventually(t, "the record after the hour", func() bool {
		recs, evs := modeChanges(t, r, node.NetworkDB)
		return len(recs) >= 2 && len(evs) >= 2
	})
	recs, evs := modeChanges(t, r, node.NetworkDB)
	if len(recs) != 2 || len(evs) != 2 || !strings.Contains(recs[1].Detail, "8 earlier mode changes") || evs[1]["not_recorded"] != "8" {
		t.Fatalf("after the hour: %d records, %d events; last %+v, %v", len(recs), len(evs), recs[len(recs)-1], evs[len(evs)-1])
	}
}

// Section 1.9 item 10: a sensor database whose Resume never returns, not
// even on its context's end, does not hold the node's stop. Close returns
// within SensorStopTimeout and a little more, and the node's own databases
// are closed and their locks released: a new start opens the evidence
// database collecting. Control: Close waits for the manager without a
// bound.
func TestCloseWithStuckSensorResume(t *testing.T) {
	g := newRig(t)
	stuck := newGate()
	t.Cleanup(stuck.open)
	r, _ := g.start(node.SensorSeams{Startup: drainOnly,
		Resume: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report {
			stuck.wait()
			return prev
		}})
	r.Tick(bg)
	stuck.entered(t, "the sensor database's Resume")
	within(t, node.SensorStopTimeout+5*time.Second, "Close", func() error { return r.Close() })
	r2, _ := g.start(node.SensorSeams{})
	m := r2.Mode(node.EvidenceDB)
	r2.Close()
	if m != c5.ModeCollecting {
		t.Fatalf("evidence database after the stop: %s", m)
	}
	// Released, the manager stops and its database is closed then, so the
	// test's directory can be removed.
	stuck.open()
	eventually(t, "the sensor database closed once the manager stopped", func() bool { return r.Mode(node.NetworkDB) == "" })
}

// Section 1.9 item 9, in the manager: a panic on the manager's goroutine
// is recovered. sensor-failed is raised once, the sensor's work stops (the
// manager steps no more and the sensor is refused), and the node goes on:
// Tick returns and every collecting stream commits. Control: no recover,
// which ends the process. The detector drive's leg comes with F3, whose
// brief moves the drive onto the manager.
func TestSensorManagerPanicContained(t *testing.T) {
	g := newRig(t)
	var calls atomic.Int32
	r, st := g.start(node.SensorSeams{Startup: drainOnly,
		Resume: func(context.Context, c5.StartupEnv, c5.StartupPolicy, c5.Report) c5.Report {
			calls.Add(1)
			panic("sensortest: a fault in the sensor's work")
		}})
	defer r.Close()
	r.Tick(bg)
	eventually(t, "sensor-failed", func() bool { return alarms(st, node.AlarmSensorFailed) == 1 })
	within(t, 2*time.Second, "Tick after the panic", func() error { r.Tick(bg); return nil })
	collecting(t, r, 1)
	r.Tick(bg)
	if n := calls.Load(); n != 1 || alarms(st, node.AlarmSensorFailed) != 1 {
		t.Fatalf("%d calls into the seam, %d alarms", n, alarms(st, node.AlarmSensorFailed))
	}
	if err := r.ServeSensor(bg, bytes.NewReader(nil)); err == nil {
		t.Fatal("the sensor was served after its work failed")
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func errorf(s string) error { return errorString(s) }

// D3's B1 on #663: a held mode change is written once its hour has passed,
// even when no later change comes, naming the mode the database is in now.
// The database opens blocked (recorded), then fails within the hour (held),
// and stays failed; after the hour a tick writes one record and one event,
// to failed, with not_recorded 1, and nothing more. Control: the flush
// removed.
func TestSensorHeldModeChangeFlushed(t *testing.T) {
	g := newRig(t)
	var startups atomic.Int32
	r, _ := g.start(node.SensorSeams{
		Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
			if startups.Add(1) > 1 {
				return c5.Report{Mode: c5.ModeFailed}
			}
			rep := c5.RunStartup(ctx, env, p)
			if db, ok := store.AsDB(rep.Store); ok {
				db.Close()
			}
			return c5.Report{Mode: c5.ModeBlocked, Unlock: rep.Unlock}
		},
		Resume: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy, prev c5.Report) c5.Report {
			return c5.Report{Mode: c5.ModeFailed, Unlock: prev.Unlock}
		}})
	defer r.Close()
	g.advance(10 * time.Minute)
	r.Tick(bg)
	eventually(t, "the database failed", func() bool { return r.Mode(node.NetworkDB) == c5.ModeFailed })
	r.Tick(bg) // a retry that stays failed: no change
	eventually(t, "the retry", func() bool { return startups.Load() == 2 })
	if recs, evs := modeChanges(t, r, node.NetworkDB); len(recs) != 1 || len(evs) != 1 {
		t.Fatalf("within the hour: %d records, %d events", len(recs), len(evs))
	}
	g.advance(time.Hour)
	r.Tick(bg)
	eventually(t, "the held change written", func() bool {
		recs, evs := modeChanges(t, r, node.NetworkDB)
		return len(recs) >= 2 && len(evs) >= 2
	})
	for range 3 {
		g.advance(time.Hour)
		n := startups.Load()
		r.Tick(bg)
		eventually(t, "a retry", func() bool { return startups.Load() > n })
	}
	recs, evs := modeChanges(t, r, node.NetworkDB)
	if len(recs) != 2 || len(evs) != 2 || recs[1].ReasonCode != string(c5.ModeFailed) || evs[1]["to"] != string(c5.ModeFailed) ||
		evs[1]["not_recorded"] != "1" || !strings.Contains(recs[1].Detail, "1 earlier mode changes") {
		t.Fatalf("after the hour: %d records, %d events; last %+v, %v", len(recs), len(evs), recs[len(recs)-1], evs[len(evs)-1])
	}
}

// D6's B1 on #663 (section 1.9 item 9): a panic in the sensor store set's
// prune, on the manager's goroutine, is recovered as the step's is.
// sensor-failed is raised once, naming the sensor, with its detail capped;
// the node goes on: Tick returns and every collecting stream commits
// within 2 s. Control: the prune outside the recover.
func TestSensorPrunePanicContained(t *testing.T) {
	g := newRig(t)
	r, st := g.start(node.SensorSeams{Prune: func(context.Context, c5.DatabaseID) error {
		panic("sensortest: a fault in the sensor database's prune")
	}})
	defer r.Close()
	eventually(t, "sensor-failed", func() bool { return alarms(st, node.AlarmSensorFailed) == 1 })
	within(t, 2*time.Second, "Tick after the panic", func() error { r.Tick(bg); return nil })
	collecting(t, r, 1)
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == node.AlarmSensorFailed && (!strings.Contains(a.Detail, sensorID) || len(a.Detail) > node.SensorFailedDetailBytes+512) {
			t.Fatalf("sensor-failed detail (%d bytes): %.200s", len(a.Detail), a.Detail)
		}
	}
	if n := alarms(st, node.AlarmSensorFailed); n != 1 {
		t.Fatalf("%d sensor-failed alarms", n)
	}
}

// D6's B4 on #663: a sensor database that C5 cannot open is retried at
// every tick, and its startup alarms are raised once, not at every try, so
// they never push another alarm out of status. With the database's file
// overwritten, 210 tries leave the collection alarm raised before them in
// status, and store-open-failed raised once. Control: the startup alarms
// raised at every try.
func TestSensorRetryAlarmsOnce(t *testing.T) {
	g := newRig(t)
	r, _ := g.start(node.SensorSeams{})
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g.c.Store.Dir, string(node.NetworkDB)+".db"), bytes.Repeat([]byte("not a database "), 512), 0o600); err != nil {
		t.Fatal(err)
	}
	var tries atomic.Int32
	r, st := g.start(node.SensorSeams{Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
		tries.Add(1)
		return c5.RunStartup(ctx, env, p)
	}})
	defer r.Close()
	if m := r.Mode(node.NetworkDB); m != c5.ModeFailed {
		t.Fatalf("network database %s", m)
	}
	st.Raise(relayID, "collection-unauthorized-line", "sensortest: a collection alarm raised before the retries")
	for range 210 {
		n := tries.Load()
		r.Tick(bg)
		eventually(t, "a retry", func() bool { return tries.Load() > n })
	}
	if n := alarms(st, "collection-unauthorized-line"); n != 1 {
		codes := map[string]int{}
		for _, a := range st.Snapshot("x").Alarms {
			codes[string(a.Database)+"/"+a.Code]++
		}
		t.Fatalf("the collection alarm is gone from status after the retries (%d); alarms %v", n, codes)
	}
	if n := alarms(st, string(c5.AlarmOpenFailed)); n != 1 {
		t.Fatalf("%d store-open-failed alarms", n)
	}
}

// D6's B3 on #663 (section 1.9 item 1, F7): a sensor database's startup
// that never returns does not hold the node's start. Start returns within
// 2 s, every collecting stream commits, and the manager's first step has
// not ended. Control: the first step back in Start.
func TestSensorStartupStuckDoesNotHoldStart(t *testing.T) {
	g := newRig(t)
	stuck := newGate()
	var r *node.Runtime
	within(t, 2*time.Second, "Start", func() error {
		r, _ = g.startNoWait(node.SensorSeams{Startup: func(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
			stuck.wait()
			return c5.RunStartup(ctx, env, p)
		}})
		return nil
	})
	// The gate opens before Close, so the manager stops within its bound.
	t.Cleanup(func() { r.Close() })
	t.Cleanup(stuck.open)
	stuck.entered(t, "the sensor database's startup")
	collecting(t, r, 1)
	select {
	case <-r.SensorFirstStep():
		t.Fatal("the first step ended while its startup is held")
	default:
	}
}

// D6's C1 on #663: the sensor-unreachable timer counts from the node's
// start, however late the intake starts (D4-73; D1's ruling 6852845352).
// The network database fails its first open, so the intake starts at a
// tick 40 s after the node's start. 60 s after the start, and 20 s after
// the intake's, with no heartbeat, the alarm stands. Control: the origin
// moved to the intake's start (D6's probe and its mutant X1).
func TestSensorUnreachableFromNodeStart(t *testing.T) {
	g := newRig(t)
	var opens atomic.Int32
	r, st := g.start(node.SensorSeams{Startup: failFirstRead(&opens)})
	defer r.Close()
	if err := r.ServeSensor(bg, bytes.NewReader(nil)); err == nil {
		t.Fatal("the intake started at the first step")
	}
	g.advance(40 * time.Second)
	r.Tick(bg)
	eventually(t, "the intake started at the tick", func() bool { return r.ServeSensor(bg, bytes.NewReader(nil)) == nil })
	if n := alarms(st, node.AlarmSensorUnreachable); n != 0 {
		t.Fatalf("40 s after the start: %d sensor-unreachable alarms", n)
	}
	g.advance(20 * time.Second)
	r.Tick(bg)
	if n := alarms(st, node.AlarmSensorUnreachable); n != 1 {
		t.Fatalf("60 s after the start, 20 s after the intake's: %d sensor-unreachable alarms", n)
	}
}
